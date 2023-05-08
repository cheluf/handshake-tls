import pyshark
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from threading import Thread
from asyncio import run_coroutine_threadsafe
import re
from ipwhois import IPWhois
import socket
import requests
from requests.exceptions import RequestException
import socket
import psutil
from tkinter import messagebox


def get_active_interface():
    active_interface = None
    max_bytes = 0

    for interface, addrs in psutil.net_if_addrs().items():
        if interface in ['lo', 'Loopback Pseudo-Interface 1']:
            continue

        for addr in addrs:
            if addr.family == socket.AF_INET:
                stats = psutil.net_io_counters(pernic=True).get(interface)

                if stats:
                    total_bytes = stats.bytes_sent + stats.bytes_recv

                    if total_bytes > max_bytes:
                        max_bytes = total_bytes
                        active_interface = interface

    return active_interface

#Alerte conform pachetelor
ABUSEIPDB_API_KEY = "ad862e094fb803af7d9b1a14eae2b46dfafe8b94ac45a497c682a1c434ad8e6564a65dce6d5f6910"

def print_alert(message, src_ip=None, dst_ip=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    alert_msg = f"{timestamp} {message}"
    if src_ip:
        alert_msg += f", Source IP: {src_ip}"
    if dst_ip:
        alert_msg += f", Destination IP: {dst_ip}"
    print(alert_msg)
    
def is_malicious_ip(ip_address):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        if response.status_code != 200:
            print(f"Error checking IP {ip_address}: {data.get('message', 'Unknown error')}")
            return False

        if data.get("data", {}).get("abuseConfidenceScore", 0) > 0:
            return True
    except RequestException as e:
        print(f"Error checking IP {ip_address}: {e}")


def alert_ftp_clear_text_auth(packet):
    if hasattr(packet.ftp, 'request_command') and packet.ftp.request_command == 'PASS':
        print_alert("ALERT: FTP Clear Text Authentication Detected")

def alert_ftp_data_transfer_unencrypted(packet):
    if hasattr(packet.ftp, 'request_command') and packet.ftp.request_command in ['STOR', 'RETR']:
        print_alert("ALERT: FTP Data Transfer Over Unencrypted Channel Detected")

def alert_weak_cipher_suites(cipher_suite):
    weak_cipher_suites = [
        '0x0005',  # SSL_RSA_WITH_RC4_128_SHA
        '0xC007',  # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        '0xC011',  # TLS_ECDHE_RSA_WITH_RC4_128_SHA
    ]
    if cipher_suite in weak_cipher_suites:
        print_alert(f"ALERT: Weak cipher suite detected ({cipher_suite_human_readable(cipher_suite)})")

def alert_insecure_tls_extensions(packet):
    if hasattr(packet.tls, 'handshake_extension_type'):
        insecure_extension_types = []
        if packet.tls.handshake_extension_type in insecure_extension_types:
            print_alert(f"ALERT: Insecure TLS extension detected ({packet.tls.handshake_extension_type})")
        

def alert_long_certificate_chain(packet):
    if hasattr(packet.tls, 'handshake_certificates_length'):
        max_certificates = 5
        cert_count = int(packet.tls.handshake_certificates_length)
        if cert_count > max_certificates:
            print_alert(f"ALERT: Long certificate chain detected ({cert_count} certificates)")

def alert_insecure_compression_methods(packet):
    if hasattr(packet.tls, 'handshake_compression_method'):
        insecure_compression_methods = ['1']
        if packet.tls.handshake_compression_method in insecure_compression_methods:
            print_alert(f"ALERT: Insecure compression method detected ({packet.tls.handshake_compression_method})")

def alert_self_signed_certificate(cert):
    if cert.subject == cert.issuer:
        print_alert(f"ALERT: Self-signed certificate detected")

def alert_weak_signature_algorithm(cert):
    weak_signature_algorithms = ['md5', 'sha1']
    signature_algorithm = cert.signature_hash_algorithm.name.lower()
    if signature_algorithm in weak_signature_algorithms:
        print_alert(f"ALERT: Weak signature algorithm detected ({signature_algorithm})")

def alert_certificate_validation(packet):
    if hasattr(packet.tls, 'handshake_certificate'):
        try:
            cert_hex = packet.tls.handshake_certificate.replace(':', '')
            cert_der = bytes.fromhex(cert_hex)
            cert_pem = b'-----BEGIN CERTIFICATE-----\n' + base64.b64encode(cert_der) + b'\n-----END CERTIFICATE-----'
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            alert_weak_signature_algorithm(cert)
            alert_self_signed_certificate(cert)
            now = datetime.utcnow()
            if now > cert.not_valid_after:
                print_alert(f"ALERT: Expired certificate detected. Not valid after {cert.not_valid_after}")
        except Exception as e:
            print_alert(f"Error parsing certificate: {e}")


def alert_weak_tls_version(tls_version):
    weak_versions = ['SSL 3.0', 'TLS 1.0', 'TLS 1.1']
    if tls_version in weak_versions:
        print_alert(f"ALERT: Weak TLS version detected ({tls_version})")

def alert_tls_message(packet):
    if hasattr(packet.tls, 'alert_message') or hasattr(packet.tls, 'alert_description'):
        alert_message = packet.tls.alert_message if hasattr(packet.tls, 'alert_message') else ""
        alert_description = packet.tls.alert_description if hasattr(packet.tls, 'alert_description') else ""
        print_alert(f"ALERT: TLS Alert Message detected ({alert_message}; {alert_description})")



#Aici am creat functii pentru variabilele din loguri, pentru a fi mai usor de citit
def content_type_human_readable(content_type):
    content_types = {
        '20': 'Change Cipher Spec',
        '21': 'Alert',
        '22': 'Handshake',
        '23': 'Application Data',
    }
    return content_types.get(content_type, f"Unknown ({content_type})")


def tcp_flags_human_readable(flags):
    flag_descriptions = []
    if flags & 0x01:
        flag_descriptions.append('FIN')
    if flags & 0x02:
        flag_descriptions.append('SYN')
    if flags & 0x04:
        flag_descriptions.append('RST')
    if flags & 0x08:
        flag_descriptions.append('PSH')
    if flags & 0x10:
        flag_descriptions.append('ACK')
    if flags & 0x20:
        flag_descriptions.append('URG')
    if flags & 0x40:
        flag_descriptions.append('ECE')
    if flags & 0x80:
        flag_descriptions.append('CWR')
    return ', '.join(flag_descriptions)

def handshake_type_human_readable(handshake_type):
    handshake_types = {
        '1': 'Client Hello',
        '2': 'Server Hello',
        '11': 'Certificate',
        '12': 'Server Key Exchange',
        '13': 'Certificate Request',
        '14': 'Server Hello Done',
        '15': 'Certificate Verify',
        '16': 'Client Key Exchange',
        '20': 'Finished',
    }
    return handshake_types.get(handshake_type, f"Unknown ({handshake_type})")

def tls_version_human_readable(hex_version):
    tls_versions = {
        '0x0300': 'SSL 3.0',
        '0x0301': 'TLS 1.0',
        '0x0302': 'TLS 1.1',
        '0x0303': 'TLS 1.2',
        '0x0304': 'TLS 1.3',
    }
    return tls_versions.get(hex_version, f"Unknown ({hex_version})")

def cipher_suite_human_readable(cipher_suite):
    cipher_suites = {
        '0x0005': 'SSL_RSA_WITH_RC4_128_SHA',
        '0x000A': 'SSL_RSA_WITH_3DES_EDE_CBC_SHA',
        '0x002F': 'TLS_RSA_WITH_AES_128_CBC_SHA',
        '0x0035': 'TLS_RSA_WITH_AES_256_CBC_SHA',
        '0xC007': 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
        '0xC009': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
        '0xC00A': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        '0xC011': 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
        '0xC013': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        '0xC014': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        '0xC02F': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        '0xC030': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        '0xCCA8': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        '0xCCA9': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        '0x1301': 'TLS_AES_128_GCM_SHA256',
        '0x1302': 'TLS_AES_256_GCM_SHA384',
        '0x1303': 'TLS_CHACHA20_POLY1305_SHA256',
    }
    return cipher_suites.get(cipher_suite, f"Unknown ({cipher_suite})")


# capturarea traficului si sortarea acestuia pentru a primi doar loguri care ne intereseaza.
active_interface = get_active_interface()
capture = pyshark.LiveCapture(interface=active_interface, bpf_filter="tcp port 21 or tcp port 443 or tcp port 990")

def print_live_tls(gui):
    for packet in capture:
        if not gui.capture_running:
            break
        log_parts = []
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_parts.append(timestamp)
        if hasattr(packet, 'ip'):
            if hasattr(packet.ip, 'src'):
                log_parts.append(f"Source IP: {packet.ip.src}")
            if hasattr(packet.ip, 'dst'):
                log_parts.append(f"Destination IP: {packet.ip.dst}")

        if hasattr(packet, 'tcp'):
            if hasattr(packet.tcp, 'srcport'):
                log_parts.append(f"Source Port: {packet.tcp.srcport}")
            if hasattr(packet.tcp, 'dstport'):
                log_parts.append(f"Destination Port: {packet.tcp.dstport}")
            if hasattr(packet.tcp, 'flags'):
                tcp_flags = tcp_flags_human_readable(int(packet.tcp.flags, 16))
                log_parts.append(f"TCP Flags: {packet.tcp.flags} ({tcp_flags})")
            if hasattr(packet.tcp, 'payload_length'):
                log_parts.append(f"Payload Length: {packet.tcp.payload_length}")

        if hasattr(packet, 'tls'):
            if hasattr(packet.tls, 'record_content_type'):
                content_type = packet.tls.record_content_type
                content_type_description = content_type_human_readable(content_type)
                log_parts.append(f"Content Type: {content_type} ({content_type_description})")

            if hasattr(packet.tls, 'record_version'):
                tls_version = tls_version_human_readable(packet.tls.record_version)
                log_parts.append(f"Version: {packet.tls.record_version} ({tls_version})")
                

            if hasattr(packet.tls, 'handshake_type'):
                handshake_type = handshake_type_human_readable(packet.tls.handshake_type)
                log_parts.append(f"Handshake Type: {packet.tls.handshake_type} ({handshake_type})")

            if hasattr(packet.tls, 'handshake_ciphersuite'):
                cipher_suite = cipher_suite_human_readable(packet.tls.handshake_ciphersuite)
                log_parts.append(f"Cipher Suite: {packet.tls.handshake_ciphersuite} ({cipher_suite})")
                alert_weak_cipher_suites(packet.tls.handshake_ciphersuite)

            if hasattr(packet.tls, 'handshake_extensions_server_name'):
                log_parts.append(f"Server Name (SNI): {packet.tls.handshake_extensions_server_name}")

            if hasattr(packet.tls, 'handshake_extensions_alpn_str'):
                log_parts.append(f"Negotiated ALPN: {packet.tls.handshake_extensions_alpn_str}")

            alert_tls_message(packet)
            alert_certificate_validation(packet)
            alert_insecure_compression_methods(packet)
            alert_insecure_tls_extensions(packet)
            alert_long_certificate_chain(packet)

        if hasattr(packet, 'ftp'):
            if hasattr(packet.ftp, 'request_command'):
                log_parts.append(f"FTP Command: {packet.ftp.request_command}")
                alert_ftp_clear_text_auth(packet)
                alert_ftp_data_transfer_unencrypted(packet)
            if hasattr(packet.ftp, 'response_code'):
                log_parts.append(f"FTP Response Code: {packet.ftp.response_code}")
            if hasattr(packet.ftp, 'response_arg'):
                log_parts.append(f"FTP Response Message: {packet.ftp.response_arg}")
        
        has_ip1 = hasattr(packet, 'ip') and hasattr(packet.ip, 'src')
        has_ip2 = hasattr(packet, 'ip') and hasattr(packet.ip, 'dst')
        has_version = hasattr(packet, 'tls') and hasattr(packet.tls, 'record_version')
        
        if has_ip1 and has_ip2 and has_version:
            alert_weak_tls_version(tls_version)
        if has_ip1 and has_ip2:
            if is_malicious_ip(packet.ip.src):
                print_alert("Malicious source IP detected", src_ip=packet.ip.src)
            if is_malicious_ip(packet.ip.dst):
                print_alert("Malicious destination IP detected", dst_ip=packet.ip.dst)
            log_line = ', '.join(log_parts)
            print(log_line)


def get_ip_info(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        return results
    except Exception as e:
        print(f"Error getting IP info: {e}")
        return None


#interfata grafica    
class LiveTLSGUI:
    def __init__(self, master):
        self.capture_running = False
        self.master = master
        master.title("Handshake TLS Analyzer")

        self.button_frame = tk.Frame(master)
        self.button_frame.grid(row=0, column=0, columnspan=3, pady=10)
        
        self.export_button = tk.Button(self.button_frame, text="Export", command=self.export_logs)
        self.export_button.pack(side=tk.LEFT, padx=5)
 
        self.start_button = tk.Button(self.button_frame, text="Start", command=self.start)
        self.start_button.pack(side=tk.LEFT, padx=5)
 
        self.stop_button = tk.Button(self.button_frame, text="Stop", command=self.stop, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=5)

        self.filter_label = tk.Label(master, text="Filter:")
        self.filter_label.grid(row=1, column=0, padx=(20, 0), pady=10, sticky="w")

        self.filter_entry = tk.Entry(master)
        self.filter_entry.grid(row=1, column=1, padx=(0, 20), pady=10, sticky="we")
        self.filter_entry.bind("<KeyRelease>", self.update_displayed_logs)

        self.text_box = scrolledtext.ScrolledText(master, wrap=tk.WORD)
        self.text_box.grid(row=2, column=0, columnspan=3, sticky="nsew")

        self.master.rowconfigure(2, weight=1)
        self.master.columnconfigure(0, weight=1)
        self.master.columnconfigure(1, weight=1)
        self.master.columnconfigure(2, weight=1)

        self.ip_search_frame = ttk.LabelFrame(master, text="Search IP:")
        self.ip_search_frame.grid(row=3, column=0, columnspan=3, padx=20, pady=10, sticky="we")

        self.ip_search_entry = tk.Entry(self.ip_search_frame)
        self.ip_search_entry.pack(side=tk.LEFT, padx=(0, 20), pady=10, fill=tk.X, expand=True)

        self.search_button = tk.Button(self.ip_search_frame, text="Search", command=self.search_ip_info)
        self.search_button.pack(side=tk.RIGHT, padx=(0, 20), pady=10)

        self.log_list = []

        self.is_running = False
        self.capture_thread = None
    
    def export_logs(self):
      file_name = "exported_logs.txt"
      with open(file_name, "w") as file:
        for log_line in self.log_list:
            file.write(log_line + "\n")
      messagebox.showinfo("Exported logs", f"Logs have been exported to {file_name}")

    def search_ip_info(self):
        search_text = self.ip_search_entry.get().strip()
        ip_info = get_ip_info(search_text)
        if ip_info:
            details = [
                f"IP: {ip_info['network']['start_address']}",
                f"ASN: {ip_info['asn']}",
                f"ASN Description: {ip_info['asn_description']}",
                f"Country: {ip_info['asn_country_code']}",
            ]
            self.show_ip_info("\n".join(details))
        else:
            self.show_ip_info("No information found for IP")
            
    def show_ip_info(self, ip_info):
        ip_info_window = tk.Toplevel(self.master)
        ip_info_window.title("IP Information")

        ip_info_label = tk.Label(ip_info_window, text=ip_info, wraplength=300)
        ip_info_label.pack(padx=20, pady=20)
    
    def update_displayed_logs(self, event):
        search_text = self.filter_entry.get().strip()
        self.text_box.delete(1.0, tk.END)
        for log_line in self.log_list:
            if self.log_matches_search(log_line, search_text):
                self.text_box.insert(tk.END, log_line + "\n")
                self.text_box.see(tk.END)
    
    def log_matches_search(self, log_line, search_text):
        search_regex = re.compile(search_text, re.IGNORECASE)
        return bool(search_regex.search(log_line))
                
    def start(self):
        if not self.is_running:
            self.is_running = True
            self.capture_running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            # Așteptați ca thread-ul de captură să se termine înainte de a porni unul nou
            if self.capture_thread is not None and self.capture_thread.is_alive():
                self.capture_thread.join()

            self.capture_thread = Thread(target=self.run_live_tls)
            self.capture_thread.start()

    def stop(self):
        if self.is_running:
            self.is_running = False
            self.capture_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

        
            if self.capture_thread is not None and self.capture_thread.is_alive():
                self.master.after(100, self.check_capture_thread)


    def check_capture_thread(self):
     if self.capture_thread is not None and self.capture_thread.is_alive():
        self.master.after(100, self.check_capture_thread)
     else:
        self.capture_thread = None

    def run_live_tls(self):
      global print
      def print_to_textbox(text):
        if self.log_matches_search(text, self.filter_entry.get().strip()):
            if "ALERT" in text:
                self.text_box.insert(tk.END, text + "\n", "alert")
            else:
                self.text_box.insert(tk.END, text + "\n")
            self.text_box.see(tk.END)
        self.log_list.append(text)
    
      print = print_to_textbox
      self.capture_thread = Thread(target=print_live_tls, args=(self,))
      self.capture_thread.start()
        

    def on_closing(self):
      if self.is_running:
        self.stop()
      self.shutdown_event_loop()
      self.master.destroy()


    def shutdown_event_loop(self):
        capture.close()
        if capture.eventloop.is_running():
            capture.eventloop.call_soon_threadsafe(capture.eventloop.stop)

if __name__ == "__main__":
    root = tk.Tk()
    gui = LiveTLSGUI(root)
    gui.text_box.tag_configure("alert", foreground="red")
    root.protocol("WM_DELETE_WINDOW", gui.on_closing)
    root.mainloop()


