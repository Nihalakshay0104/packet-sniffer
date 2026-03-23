import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff, IP, TCP, UDP
import threading
from collections import defaultdict
import csv
import time
from queue import Queue

running = False
counter = 0

ip_count = defaultdict(int)
protocol_count = {"TCP": 0, "UDP": 0, "Other": 0}
port_count = defaultdict(int)

packets_log = []
packet_queue = Queue()

selected_filter = "ALL"

# ---------------- PACKET PROCESSING ----------------
def process_packet(packet):
    if packet.haslayer(IP):
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

        packet_queue.put((src, dst, proto, port))

# ---------------- UI UPDATE ----------------
def update_ui():
    global counter

    while not packet_queue.empty():
        src, dst, proto, port = packet_queue.get()

        counter += 1
        counter_label.config(text=f"Packets: {counter}")

        ip_count[src] += 1
        protocol_count[proto] += 1
        port_count[str(port)] += 1

        packets_log.append([time.strftime("%H:%M:%S"), src, dst, proto, port])

        tree.insert("", "end", values=(src, dst, proto, port))

    root.after(100, update_ui)

# ---------------- ANALYSIS ----------------
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

    # Simple anomaly rules
    for ip, count in ip_count.items():
        if count > 100:
            result += f"\n[!] High traffic: {ip}"

    # Port scan detection
    port_tracker = defaultdict(set)
    for pkt in packets_log:
        port_tracker[pkt[1]].add(pkt[4])

    for ip, ports in port_tracker.items():
        if len(ports) > 15:
            result += f"\n[!] Port scan suspected: {ip}"

    output.delete(1.0, tk.END)
    output.insert(tk.END, result)

# ---------------- EXPORT ----------------
def export_csv():
    if not packets_log:
        output.insert(tk.END, "\nNo data to export\n")
        return

    file = filedialog.asksaveasfilename(defaultextension=".csv")
    if not file:
        return

    with open(file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Time","Source","Destination","Protocol","Port"])
        writer.writerows(packets_log)

    output.insert(tk.END, f"\nSaved to {file}\n")

# ---------------- CONTROL ----------------
def start():
    global running
    running = True
    threading.Thread(
        target=lambda: sniff(prn=process_packet, stop_filter=lambda x: not running),
        daemon=True
    ).start()

def stop():
    global running
    running = False

def clear():
    global counter
    for row in tree.get_children():
        tree.delete(row)

    counter = 0
    counter_label.config(text="Packets: 0")

    ip_count.clear()
    protocol_count.update({"TCP":0,"UDP":0,"Other":0})
    port_count.clear()
    packets_log.clear()

def set_filter(val):
    global selected_filter
    selected_filter = val

# ---------------- GUI ----------------
root = tk.Tk()
root.title("Enhanced Packet Sniffer (Stable)")
root.geometry("950x650")

columns = ("Source","Destination","Protocol","Port")
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
tk.Button(frame, text="Analyze", command=analyze).pack(side=tk.LEFT)
tk.Button(frame, text="Export CSV", command=export_csv).pack(side=tk.LEFT)

filter_var = tk.StringVar(value="ALL")
ttk.Combobox(frame, textvariable=filter_var, values=["ALL","TCP","UDP"]).pack(side=tk.LEFT)
filter_var.trace("w", lambda *args: set_filter(filter_var.get()))

output = tk.Text(root, height=12)
output.pack(fill=tk.BOTH)

update_ui()
root.mainloop()
