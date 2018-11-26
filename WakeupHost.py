#!/usr/bin/python3

import dbus
import sys

def WakeupHost(hostname):
    bus = dbus.SystemBus()
    Hosts = bus.get_object('de.yavdr.hostwakeup', '/Hosts')
    return Hosts.Wakeup(hostname, dbus_interface = 'de.yavdr.hostwakeup')

if __name__ == "__main__":
    if sys.argv[1]:
        WakeupHost(sys.argv[1])
