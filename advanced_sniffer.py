import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff, IP, TCP, UDP
import threading
from collections import defaultdict
import csv
import time

running = False
counter = 0

ip_count = defaultdict(int)
protocol_count = {"TCP": 0, "UDP": 0, "Other": 0}

packets_log = []

# Packet processing
def process_packet(packet):
    global counter

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        else:
            proto = "Other"

        counter += 1
        counter_label.config(text=f"Packets: {counter}")

        ip_count[src] += 1
        protocol_count[proto] += 1

        packets_log.append([time.strftime("%H:%M:%S"), src, dst, proto])

        tree.insert("", "end", values=(src, dst, proto))

        print(packets_log[-1])

# Sniffing
def start_sniffing():
    global running
    running = True
    sniff(prn=process_packet, stop_filter=lambda x: not running)

def start():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()

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
    protocol_count.update({"TCP": 0, "UDP": 0, "Other": 0})
    packets_log.clear()

# Analysis
def analyze():
    result = "\nTop IPs:\n"
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        result += f"{ip}: {count}\n"

    result += "\nProtocols:\n"
    for proto, count in protocol_count.items():
        result += f"{proto}: {count}\n"

    for ip, count in ip_count.items():
        if count > 50:
            result += f"\n[!] Suspicious: {ip} high traffic"

    output.delete(1.0, tk.END)
    output.insert(tk.END, result)

# Export CSV
def export_csv():
    if not packets_log:
        output.delete(1.0, tk.END)
        output.insert(tk.END, "No data to export. Capture packets first.")
        return

    file = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        title="Save CSV File"
    )

    if not file:
        return

    try:
        with open(file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Time", "Source", "Destination", "Protocol"])
            writer.writerows(packets_log)

        output.delete(1.0, tk.END)
        output.insert(tk.END, f"Export successful! Saved to:\\n{file}")

    except Exception as e:
        output.delete(1.0, tk.END)
        output.insert(tk.END, f"Error exporting file:\\n{str(e)}")

# GUI
root = tk.Tk()
root.title("Advanced Packet Sniffer")
root.geometry("900x600")

columns = ("Source IP", "Destination IP", "Protocol")
tree = ttk.Treeview(root, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=200)

tree.pack(fill=tk.BOTH, expand=True)

counter_label = tk.Label(root, text="Packets: 0")
counter_label.pack()

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Button(frame, text="Start", command=start).pack(side=tk.LEFT, padx=5)
tk.Button(frame, text="Stop", command=stop).pack(side=tk.LEFT, padx=5)
tk.Button(frame, text="Clear", command=clear).pack(side=tk.LEFT, padx=5)
tk.Button(frame, text="Analyze", command=analyze).pack(side=tk.LEFT, padx=5)
tk.Button(frame, text="Export CSV", command=export_csv).pack(side=tk.LEFT, padx=5)

output = tk.Text(root, height=10)
output.pack(fill=tk.BOTH)

root.mainloop()
