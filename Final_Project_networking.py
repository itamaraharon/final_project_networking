import tkinter as tk
from tkinter import ttk
from scapy.all import *
import threading
import time

PORTS_DHCP = (67, 68)
COLOR_F = '#6F87A1'
COLOR_P = '#62B27F'
SELECT_IN: str = "0"
SELECT_OUT: str = "0"

thread = None
switch: bool = False

# Function that prints the sniffed pact.
def print_d(packet, proto, layer):
    print("{0}: {1} Bytes, SRC-MAC: {2}, DST-MAC: {3}, SRC-PORT: {4}, DST-PORT: {5}, SRC-IP: {6}, DST-IP: {7},"
          .format(proto, (len(packet[layer])), packet.src, packet.dst, packet.sport, packet.dport, packet[IP].src,
                  packet[IP].dst))

# The function of starting to sniff
def sniffing():
    print("[*] Start sniffing...")
    sniff(prn=action, stop_filter=stop_sniffing)

# Function that checks if the user has selected filter and which filter.
def testing(packet):
    global SELECT_IN, SELECT_OUT
    Result_s: bool = True
    if (trn_in.get() == 1 or trn_out.get() == 1) and (comboExample.get() != "Select") and (Entry1.get() != ""):
        Result_s = False
        if comboExample.get() == "PORT":
            SELECT_IN = int()
            SELECT_OUT = int()
            if packet.getlayer(IP) is not None:
                if packet.haslayer(TCP) is not None or packet.haslayer(UDP) is not None:
                    if trn_in.get() == 1:
                        SELECT_IN = packet.dport
                    else:
                        SELECT_IN = None
                    if trn_out.get() == 1:
                        SELECT_OUT = packet.sport
                    else:
                        SELECT_OUT = None
                try:
                    if (int(Entry1.get()) == SELECT_OUT) or (int(Entry1.get()) == SELECT_IN):
                        Result_s = True
                except Exception:
                    Result_s = False
        if comboExample.get() == "IP":
            if packet.getlayer(IPv6) is None:
                if packet.getlayer(IP) is not None:
                    if trn_in.get() == 1:
                        SELECT_IN = str(packet[IP].src)
                    else:
                        SELECT_IN = None
                    if trn_out.get() == 1:
                        SELECT_OUT = str(packet[IP].dst)
                    else:
                        SELECT_OUT = None
                    if (Entry1.get() == SELECT_OUT) or (Entry1.get() == SELECT_IN):
                        Result_s = True

        if comboExample.get() == "MAC":
            SELECT_IN = str()
            SELECT_OUT = str()
            if trn_in.get() == 1:
                SELECT_IN = packet.src
            else:
                SELECT_IN = None
            if trn_out.get() == 1:
                SELECT_OUT = packet.dst
            else:
                SELECT_OUT = None
            if (Entry1.get() == SELECT_OUT) or (Entry1.get() == SELECT_IN):
                Result_s = True

    return Result_s

# Function that checks what type each packet
def action(packet):
    try:
        if testing(packet):
            if packet.getlayer(ICMP) is not None:
                if var_icmp.get() == 1 or var_all.get() == 1:
                    print(('ICMP:{0} Bytes, SRC-MAC: {1}, DST-MAC: {2}, SRC-IP: {3}, DST-IP: {4}, '
                           .format((len(packet[ICMP])), packet.src, packet.dst, packet[IP].src, packet[IP].dst)))

            elif packet.getlayer(ARP) is not None:
                if var_arp.get() == 1 or var_all.get() == 1:
                    print(packet.sprintf(
                        f'ARP:{len(packet[ARP])} Bytes, SRC-MAC: {packet.src}, DST-MAC: {packet.dst},'
                        f' SRC-IP: %ARP.pdst%, DST-IP: '
                        f'%ARP.psrc% '))

            elif packet.getlayer(IP) is not None:
                if packet.haslayer(TCP):
                    if packet[TCP].dport == 443:
                        if var_https_in.get() == 1 or var_all.get() == 1:
                            print_d(packet, "HTTPS-IN", "TCP")
                    elif packet[TCP].sport == 443:
                        if var_https_out.get() == 1 or var_all.get() == 1:
                            print_d(packet, "HTTPS-OUT", "TCP")
                    else:
                        if var_tcp.get() == 1 or var_all.get() == 1:
                            print_d(packet, "TCP", "TCP")
                elif packet.haslayer(UDP):
                    if packet.getlayer(DNS) is not None:
                        if var_dns.get() == 1 or var_all.get() == 1:
                            print_d(packet, "DNS", "UDP")
                    elif packet[UDP].sport or packet[UDP].sport == PORTS_DHCP:
                        if var_dhcp.get() == 1 or var_all.get() == 1:
                            print_d(packet, "DHCP", "UDP")
                    else:
                        if var_udp.get() == 1 or var_all.get() == 1:
                            print_d(packet, "UDP", "UDP")
            elif packet.getlayer(IPv6) is not None:
                if var_other.get() == 1 or var_all.get() == 1:
                    print(
                        "IPv6: {0} Bytes, SRC-MAC: {1}, DST-MAC: {2}, IP: {3}, DST-IP: {4}".format((len(packet[IPv6])),
                                                                                                   packet.src,
                                                                                                   packet.dst,
                                                                                                   packet[IPv6].src,
                                                                                                   packet[IPv6].dst))
            else:
                if var_other.get() == 1 or var_all.get() == 1:
                    print(packet)
    except Exception as e:
        print(e)


def stop_sniffing(x):
    global switch
    return switch


def start_button():
    global switch
    global thread
    if (thread is None) or (not thread.is_alive()):
        switch = False
        thread = threading.Thread(target=sniffing)
        thread.start()
    else:
        print('already running')


def stop_button():

    global switch
    switch = True
    time.sleep(1)
    print('stopping')


def frame_quit():
    global switch
    switch = True
    print("[*] closed down sniffer")
    quit()


# --- main ---

root = tk.Tk()

canvas = tk.Canvas(root, height=360, width=300)
canvas.grid()

frame = tk.Frame(root, bg=COLOR_F)
frame.place(relheight=1, relwidth=1)

lbl1 = tk.Label(frame, text="Wireshark", fg='blue', bg=COLOR_F, font=(None, 15))
lbl1.place(relx=0.5, y=28, anchor='center')

btn_str = tk.Button(frame, text="Start sniffing", command=lambda: start_button())
btn_str.place(x=12, y=60, relheight=0.1, relwidth=0.35)

btn_stp = tk.Button(frame, text="Stop sniffing", command=lambda: stop_button())
btn_stp.place(x=126, y=60, relheight=0.1, relwidth=0.35)

btn_q = tk.Button(frame, text="Quit", command=lambda: frame_quit())
btn_q.place(x=240, y=60, relheight=0.1, relwidth=0.18)

lbl_e_n = tk.Label(frame, text="Enter number: ", fg="#C0111F", bg=COLOR_F)
lbl_e_n.place(x=10, y=120)

Entry1 = tk.Entry(frame)
Entry1.place(x=125, y=120, relheight=0.07, relwidth=0.55)

lbl_f_tr = tk.Label(frame, text="Filter Transport: ", fg="#C0111F", bg=COLOR_F)
lbl_f_tr.place(x=10, y=160)

trn_in = tk.IntVar()
tk.Checkbutton(frame, text="IN", bg=COLOR_F, variable=trn_in).place(x=130, y=160)

trn_out = tk.IntVar()
tk.Checkbutton(frame, text="OUT", bg=COLOR_F, variable=trn_out).place(x=190, y=160)

lbl_f_ty = tk.Label(frame, text="Filter Type: ", fg="#C0111F", bg=COLOR_F)
lbl_f_ty.place(x=10, y=200)

comboExample = ttk.Combobox(frame,
                            values=[
                                "Select",
                                "IP",
                                "MAC",
                                "PORT"])
comboExample.place(x=120, y=200, relheight=0.06, relwidth=0.33)
comboExample.current(0)

frame_p = tk.Label(root, bg=COLOR_P)
frame_p.place(y=235, relheight=1, relwidth=1)

lbl_f_pr = tk.Label(frame_p, text="Filter Protocol", fg='blue', bg=COLOR_P)
lbl_f_pr.place(x=1, y=1)

var_all = tk.IntVar(value=1)
tk.Checkbutton(frame_p, text="all", bg=COLOR_P, variable=var_all).place(x=2, y=25)

var_dhcp = tk.IntVar()
tk.Checkbutton(frame_p, text="DHCP", bg=COLOR_P, variable=var_dhcp).place(x=2, y=60)

var_tcp = tk.IntVar()
tk.Checkbutton(frame_p, text="TCP", bg=COLOR_P, variable=var_tcp).place(x=2, y=90)

var_udp = tk.IntVar()
tk.Checkbutton(frame_p, text="UDP", bg=COLOR_P, variable=var_udp).place(x=75, y=25)

var_arp = tk.IntVar()
tk.Checkbutton(frame_p, text="ARP", bg=COLOR_P, variable=var_arp).place(x=75, y=60)

var_icmp = tk.IntVar()
tk.Checkbutton(frame_p, text="ICMP", bg=COLOR_P, variable=var_icmp).place(x=75, y=90)

var_dns = tk.IntVar()
tk.Checkbutton(frame_p, text="DNS", bg=COLOR_P, variable=var_dns).place(x=145, y=25)

var_https_in = tk.IntVar()
tk.Checkbutton(frame_p, text="HTTPS-IN", bg=COLOR_P, variable=var_https_in).place(x=145, y=60)

var_https_out = tk.IntVar()
tk.Checkbutton(frame_p, text="HTTPS-OUT", bg=COLOR_P, variable=var_https_out).place(x=145, y=90)

var_other = tk.IntVar()
tk.Checkbutton(frame_p, text="Other", bg=COLOR_P, variable=var_other).place(x=220, y=25)

root.mainloop()

frame_quit()
