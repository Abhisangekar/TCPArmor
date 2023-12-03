from scapy.all import *
import optparse as op
import pandas as pd 
import numpy as np
import sklearn
import joblib
import warnings
from colorama import Fore, Style
import tkinter as tk
from tkinter import messagebox
import subprocess as sp
from system_IP_mac import IP_address, mac_address


popup_opened = False        #initial condition that the pop up is not opened

def parsing():
    parser = op.OptionParser()
    parser.add_option('-i','--interface', dest='interface', help='Specify network interface')
    parser.add_option("-m","--mode", dest='mode', help="Select mode between automatic and mannual")
    return parser.parse_args()

(options, arguments) = parsing()
interface = options.interface
mode = options.mode

RED = Fore.RED
YELLOW = Fore.YELLOW
RESET = Style.RESET_ALL
warnings.filterwarnings("ignore", category=UserWarning)

window = tk.Tk()
window.withdraw()

def file_write(IP, MAC):
    file = open('Blocked.txt', 'w')
    file.writelines([IP," ", MAC])

def open_popup(source_IP, source_mac, dest_IP_address, dst_mac):
    global popup_opened
    if not popup_opened:
        create_popup(source_IP, source_mac, dest_IP_address, dst_mac)
    popup_opened = True

def block_system(source_IP, source_mac, dest_IP_address, dst_mac):
    # Block an IP address: sudo iptables -A INPUT -s <IP_ADDRESS> -j DROP
    # Unblock an IP address: sudo iptables -D INPUT -s <IP_ADDRESS> -j DROP
    # Block a MAC address: sudo ebtables -A INPUT -s <MAC_ADDRESS> -j DROP
    # Unblock  MAC address: sudo ebtables -D INPUT -s <MAC_ADDRESS> -j DROP
    global interface
    host_IP = IP_address(interface)
    host_mac = mac_address(interface)
    if host_IP == source_IP:
        sp.call(['iptables', '-A', 'INPUT', '-s', dest_IP_address, '-j', 'DROP'])
        sp.call(['ebtables', '-A', 'INPUT', '-s', dst_mac, '-j', 'DROP'])
        print('[+] Threat neutralized, Addresses blocked ', dest_IP_address,' and '+dst_mac)
        file_write(dest_IP_address, dst_mac)

    elif host_IP == dest_IP_address:
        sp.call(['iptables', '-A', 'INPUT', '-s', source_IP, '-j', 'DROP'])
        sp.call(['ebtables', '-A', 'INPUT', '-s', source_mac, '-j', 'DROP'])
        print('[+] Threat neutralized, Addresses blocked ', source_IP,' and '+source_mac)
        file_write(source_IP, source_mac)

def button_click(response,source_IP, source_mac, dest_IP_address, dst_mac):
    if response == "Neutralize":
        block_system(source_IP, source_mac, dest_IP_address, dst_mac)
    elif response == "Skip":
        pass
    window.destroy()

def create_popup(source_IP, source_mac, dest_IP_address, dst_mac):
    popup = tk.Toplevel(window)
    popup.title("Warning!")
    popup.attributes("-topmost", True)
    popup.resizable(False, False)
    message = tk.Label(popup, text="Suspecious activity Detected")
    message.pack(pady = 10)
    skip_button = tk.Button(popup, text="Skip", width=10, command=lambda: button_click("Skip",source_IP, source_mac, dest_IP_address, dst_mac))
    skip_button.pack(side=tk.LEFT, padx=10)
    neutralize_button = tk.Button(popup, text='Neutralize', width=10, command=lambda: button_click("Neutralize",source_IP, source_mac, dest_IP_address, dst_mac))
    neutralize_button.pack(side=tk.RIGHT, padx=10)


model = joblib.load('random_forest_model.joblib')


def packethandler(packet):
    if 'IP' in packet:
        data = []
        source_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        source_IP = packet[IP].src
        dest_IP_address = packet[IP].dst
        IP_data = [packet[IP].len, packet[IP].ttl, int(packet[IP].flags), packet[IP].proto, packet[IP].chksum]
        if packet[IP].proto == 6:
            TCP_data = [packet[TCP].sport, packet[TCP].dport, packet[TCP].seq, packet[TCP].ack, int(packet[TCP].flags), packet[TCP].window, packet[TCP].chksum]
        else:
            TCP_data = [0,0,0,0,0,0,0,0]
        data.extend(IP_data)
        data.extend(TCP_data)
        if TCP_data == [0,0,0,0,0,0,0,0]:
            pass
        else:
            TCP_prediction(data, source_IP,source_mac, dest_IP_address, dst_mac)
            #return data, source_IP, dest_IP_address
    else:
        pass

def TCP_prediction(data,source_IP, source_mac, dest_IP_address, dst_mac):
    prediction = model.predict([data])
    if (prediction == 1):
        print(RED+"[-] Warning! Suspecious activity detected from IP " +dest_IP_address +" and MAC address " + dst_mac + RESET)
        response(source_IP, source_mac, dest_IP_address, dst_mac)
        window.mainloop()
    elif (prediction == 0):
        pass

def response(source_IP, source_mac, dest_IP_address, dst_mac):
    #mode = global mode
    if mode == "mannual":
        open_popup(source_IP, source_mac, dest_IP_address, dst_mac)
    elif mode == "automatic":
        block_system(source_IP, source_mac, dest_IP_address, dst_mac)

print("[+] Monitoring started at interface", interface, "................")
sniff(iface= interface,prn=packethandler)
