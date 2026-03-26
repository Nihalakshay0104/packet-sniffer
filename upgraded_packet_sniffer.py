# FIXED + STABLE VERSION

import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff, IP, TCP, UDP, DNSQR, Raw
from scapy.utils import wrpcap
import threading
from collections import defaultdict, deque
import csv
import time
from queue import Queue
import requests
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

running = False
counter = 0


dst_count = defaultdict(int)

ip_count = defaultdict(int)
protocol_count = {"TCP": 0, "UDP": 0, "Other": 0}
port_count = defaultdict(int)
country_count = defaultdict(int)

packets_log = []
packet_queue = Queue()
captured_packets = []

selected_filter = "ALL"

ip_cache = {}
packet_times = deque(maxlen=100)
packet_rates = deque(maxlen=50)

alerted_ips = set()
last_packet_check = time.time()
packet_counter_window = 0


SUSPICIOUS_PORTS = {
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    110,  # POP3
    139,  # NetBIOS
    143,  # IMAP
    443,  # HTTPS
    445,  # SMB
    3389  # RDP
}

# -------- IP INFO --------
def get_ip_info(ip):
    if ip in ip_cache:
        return ip_cache[ip]

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        country = r.get("country", "?")
        isp = r.get("isp", "?")
        result = (country, f"{country} | {isp}")
        ip_cache[ip] = result
        return result
    except:
        return "?", "Unknown"

def traffic_analyzer():
    if counter == 0:
        output.delete(1.0, tk.END)
        output.insert(tk.END, "No traffic captured yet.\n")
        return

    result = "=== 🧠 TRAFFIC ANALYSIS REPORT ===\n\n"

    # 🔝 Top source IPs
    result += "Top Talkers:\n"
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        result += f"  {ip}: {count} packets\n"

    # 🎯 Top destinations
    result += "\nMost Targeted Destinations:\n"
    if dst_count:
        for ip, count in sorted(dst_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            result += f"  {ip}: {count} hits\n"
    else:
        result += "  No data\n"

    # 🚪 Suspicious ports
    result += "\nSuspicious Port Activity:\n"
    found = False
    for port, count in port_count.items():
        try:
            try:
                if int(port) in SUSPICIOUS_PORTS:
                    result += f"  Port {port}: {count} packets\n"
            except:
                pass
        except:
            continue

    if not found:
        result += "  None detected\n"

    # 📊 Protocol distribution
    total = sum(protocol_count.values()) or 1
    result += "\nProtocol Breakdown:\n"
    for proto, count in protocol_count.items():
        percent = (count / total) * 100
        result += f"  {proto}: {percent:.1f}%\n"

    # 🚨 Anomaly detection
    result += "\nAnomaly Detection:\n"

    alerts_found = False

    for ip, count in ip_count.items():
        if count > 200:
            result += f"  🚨 High traffic from {ip}\n"
            alerts_found = True

    if len(port_count) > 50:
        result += "  🚨 Possible port scan (many ports hit)\n"
        alerts_found = True

    if ip_count:
        top_ip, top_count = max(ip_count.items(), key=lambda x: x[1])
        if top_count > (counter * 0.5):
            result += f"  🚨 {top_ip} dominates traffic (>50%)\n"
            alerts_found = True

    if not alerts_found:
        result += "  No major anomalies detected\n"

    result += "\n=== END OF REPORT ==="

    output.delete(1.0, tk.END)
    output.insert(tk.END, result)

    
# -------- PACKET PROCESSING --------
def process_packet(packet):
    global packet_counter_window

    if packet.haslayer(IP):
        packet_times.append(time.time())
        packet_counter_window += 1
        captured_packets.append(packet)

        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            port = packet[UDP].dport
        else:
            proto = "Other"
            port = "-"

        if selected_filter != "ALL" and proto != selected_filter:
            return

        extra = ""

        if packet.haslayer(DNSQR):
            try:
                extra += "[DNS] " + packet[DNSQR].qname.decode()
            except:
                pass

        if packet.haslayer(Raw):
            try:
                data = packet[Raw].load.decode(errors="ignore")
                if data.startswith("GET") or data.startswith("POST"):
                    extra += " [HTTP] " + data.split("\\r\\n")[0]
            except:
                pass

        country, info = get_ip_info(src)
        country_count[country] += 1

        packet_queue.put((src, dst, proto, port, info, extra))

# -------- UI UPDATE --------
def update_ui():
    global counter

    while not packet_queue.empty():
        src, dst, proto, port, info, extra = packet_queue.get()

        counter += 1
        counter_label.config(text=f"Packets: {counter}")

        ip_count[src] += 1
        protocol_count[proto] += 1
        port_count[str(port)] += 1
        dst_count[dst] += 1

        packets_log.append([time.strftime("%H:%M:%S"), src, dst, proto, port])

        # Limit rows (prevents UI freeze)
        if len(tree.get_children()) > 1000:
            tree.delete(tree.get_children()[0])

        tree.insert("", "end", values=(src, dst, proto, port, info))

        if extra:
            output.insert(tk.END, extra + "\n")

    root.after(100, update_ui)

# -------- RATE GRAPH --------
def start_rate_graph():
    def run():
        fig, ax = plt.subplots()

        def update(frame):
            now = time.time()
            count = sum(1 for t in packet_times if now - t <= 1)
            packet_rates.append(count)

            ax.clear()
            ax.plot(list(packet_rates))
            ax.set_title("Packets per Second")
            ax.set_xlabel("Time")
            ax.set_ylabel("Packets/sec")

        # 🔥 IMPORTANT: store animation in variable
        ani = FuncAnimation(fig, update, interval=1000)

        plt.show()

    threading.Thread(target=run, daemon=True).start()
    ax.set_ylim(0, max(packet_rates) + 10)

# -------- GEO --------
def show_geo_stats():
    result = "=== GEO ===\n\n"
    for c, count in sorted(country_count.items(), key=lambda x: x[1], reverse=True):
        result += f"{c}: {count}\n"

    output.delete(1.0, tk.END)
    output.insert(tk.END, result)

# -------- ALERTS --------
def check_alerts():
    global packet_counter_window, last_packet_check

    now = time.time()

    if now - last_packet_check >= 1:
        if packet_counter_window > 200:
            output.insert(tk.END, f"[ALERT] Spike: {packet_counter_window} pps\n")

        packet_counter_window = 0
        last_packet_check = now

    for ip, count in ip_count.items():
        if count > 100 and ip not in alerted_ips:
            alerted_ips.add(ip)
            output.insert(tk.END, f"[ALERT] Scan: {ip}\n")

    root.after(1000, check_alerts)

# -------- EXPORT --------
def export_csv():
    file = filedialog.asksaveasfilename(defaultextension=".csv")
    if file:
        with open(file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Time","Source","Destination","Protocol","Port"])
            writer.writerows(packets_log)

# -------- PCAP --------
def save_pcap():
    file = filedialog.asksaveasfilename(defaultextension=".pcap")
    if file:
        wrpcap(file, captured_packets)

# -------- CONTROL --------
def start():
    global running
    running = True

    def sniff_loop():
        while running:
            sniff(prn=process_packet, timeout=1)

    threading.Thread(target=sniff_loop, daemon=True).start()

def stop():
    global running
    running = False

def clear():
    global counter
    tree.delete(*tree.get_children())
    counter = 0
    counter_label.config(text="Packets: 0")


def analyze():
    result = "=== TRAFFIC REPORT ===\n\n"

    result += "Top Source IPs:\n"
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        result += f"{ip}: {count}\n"

    result += "\nTop Ports:\n"
    for port, count in sorted(port_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        result += f"{port}: {count}\n"

    total = sum(protocol_count.values()) or 1
    result += "\nProtocol Distribution:\n"
    for p, c in protocol_count.items():
        result += f"{p}: {c} ({(c/total)*100:.1f}%)\n"

    output.delete(1.0, tk.END)
    output.insert(tk.END, result)




def traffic_analyzer():
    result = "=== 🧠 TRAFFIC ANALYSIS REPORT ===\n\n"

    # 🔝 Top source IPs
    result += "Top Talkers:\n"
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        result += f"  {ip}: {count} packets\n"

    # 🎯 Top destinations
    result += "\nMost Targeted Destinations:\n"
    for ip, count in sorted(dst_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        result += f"  {ip}: {count} hits\n"

    # 🚪 Suspicious ports
    result += "\nSuspicious Port Activity:\n"
    found = False
    for port, count in port_count.items():
        if port != "-" and int(port) in SUSPICIOUS_PORTS:
            result += f"  Port {port}: {count} packets\n"
            found = True
    if not found:
        result += "  None detected\n"

    # 📊 Protocol distribution
    total = sum(protocol_count.values()) or 1
    result += "\nProtocol Breakdown:\n"
    for proto, count in protocol_count.items():
        percent = (count / total) * 100
        result += f"  {proto}: {percent:.1f}%\n"

    # 🚨 Anomaly hints
    result += "\nAnomaly Detection:\n"

    # High traffic IP
    for ip, count in ip_count.items():
        if count > 200:
            result += f"  🚨 High traffic from {ip}\n"

    # Too many ports accessed
    if len(port_count) > 50:
        result += "  🚨 Possible port scan (many ports hit)\n"

    # Single IP dominating
    if ip_count:
        top_ip, top_count = max(ip_count.items(), key=lambda x: x[1])
        if top_count > (counter * 0.5):
            result += f"  🚨 {top_ip} dominates traffic (>50%)\n"

    result += "\n=== END OF REPORT ==="

    output.delete(1.0, tk.END)
    output.insert(tk.END, result)

    
# -------- GUI --------
root = tk.Tk()
root.title("Packet Sniffer PRO ⚡")
root.geometry("1100x700")

columns = ("Source","Destination","Protocol","Port","Info")
tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=200)

tree.pack(fill=tk.BOTH, expand=True)

counter_label = tk.Label(root, text="Packets: 0")
counter_label.pack()

frame = tk.Frame(root)
frame.pack()

tk.Button(frame, text="Start", command=start).pack(side=tk.LEFT)
tk.Button(frame, text="Stop", command=stop).pack(side=tk.LEFT)
tk.Button(frame, text="Clear", command=clear).pack(side=tk.LEFT)
tk.Button(frame, text="Export CSV", command=export_csv).pack(side=tk.LEFT)
tk.Button(frame, text="Rate Graph", command=start_rate_graph).pack(side=tk.LEFT)
tk.Button(frame, text="Geo Stats", command=show_geo_stats).pack(side=tk.LEFT)
tk.Button(frame, text="Save PCAP", command=save_pcap).pack(side=tk.LEFT)
tk.Button(frame, text="Analyze Traffic 🧠", command=traffic_analyzer).pack(side=tk.LEFT)

output = tk.Text(root, height=12)
output.pack(fill=tk.BOTH)

update_ui()
check_alerts()
root.mainloop()
