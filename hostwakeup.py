#!/usr/bin/python

import avahi
import dbus
import dbus.service
import getopt
import gobject
import netifaces
import os
import signal
import re
import socket
import SocketServer
import struct
import sys
import threading

from dbus.mainloop.glib import DBusGMainLoop

service_type = "_host-wakeup._tcp"

dbus_interface = "de.yavdr.hostwakeup"
mac_interface = "eth0"
host_file = "/var/cache/hostwakeup/hosts.conf"


def get_mac(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"].lower()

def get_broadcast_addr(interface):
    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["broadcast"]

def wake_on_lan(macaddress, broadcast):
    if len(macaddress) == 12:
        pass
    elif len(macaddress) == 12 + 5:
        sep = macaddress[2]
        macaddress = macaddress.replace(sep, "")
    else:
        raise ValueError("incorrect MAC address format")
    data = "".join(["FFFFFFFFFFFF", macaddress * 20])
    send_data = "" 
    for i in range(0, len(data), 2):
        send_data = "".join([send_data, struct.pack("B", int(data[i: i + 2], 16))])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(send_data, (broadcast, 7))

def read_hosts(file):
    hosts = {}
    try:
        with open(file, "r") as f:
            lines = f.readlines()
            for line in lines:
                line = line.rstrip("\n").strip()
                match = re.search("host=(.+),mac=(.+)", line)
                host = match.group(1)
                mac = match.group(2)
                if match and host:
                    hosts[host.lower()] = mac.lower()
    except:
        pass
    return hosts

def write_hosts(file, hosts):
    try:
        if len(hosts) == 0:
            os.remove(file)
        else:
            with open(file, "w") as f:
                for host in hosts:
                    f.write("host=%s,mac=%s\n" % (host, hosts[host]))
    except:
        pass


class AvahiService:
    def __init__(self, avahi_server, name, type, port, *subtypes):
        self.server = avahi_server
        self.name = name
        self.type = type
        self.port = port
        self.subtypes = subtypes
        self.group = None

    def Publish(self, txts):
        if not self.group:
            g = bus.get_object(avahi.DBUS_NAME, self.server.EntryGroupNew())
            self.group = dbus.Interface(g, avahi.DBUS_INTERFACE_ENTRY_GROUP)
        else:
            self.group.Reset()
        if self.group.IsEmpty():
            self.group.AddService(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, dbus.UInt32(0),
                                  self.name, self.type, "", "", dbus.UInt16(self.port), txts)
            for subtype in self.subtypes:
                if not subtype.endswith("._sub." + self.type):
                    subtype = subtype + "._sub." + self.type
                self.group.AddServiceSubtype(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, dbus.UInt32(0),
                                             self.name, self.type, "", subtype)
            self.group.Commit()


class AvahiBrowser:
    def __init__(self, avahi_server, host_service, protocol, type):
        self.avahi_server = avahi_server
        self.host_service = host_service
        self.net_lock = threading.Lock()
        self.net_services = {}
        b = avahi_server.ServiceBrowserNew(avahi.IF_UNSPEC, protocol, type, "", dbus.UInt32(0))
        self.browser = dbus.Interface(bus.get_object(avahi.DBUS_NAME, b), avahi.DBUS_INTERFACE_SERVICE_BROWSER)
        self.browser.connect_to_signal("ItemNew", self.new_handler)
        self.browser.connect_to_signal("ItemRemove", self.remove_handler)

    def new_handler(self, interface, protocol, name, type, domain, flags):
        r = avahi_server.ServiceResolverNew(interface, protocol, name, type, domain, avahi.PROTO_UNSPEC, dbus.UInt32(0))
        self.resolver = dbus.Interface(bus.get_object(avahi.DBUS_NAME, r), avahi.DBUS_INTERFACE_SERVICE_RESOLVER)
        self.resolver.connect_to_signal("Found", self.service_resolved)

    def remove_handler(self, interface, protocol, name, type, domain, flags):
        self.net_lock.acquire()
        if name in self.net_services:
            del self.net_services[name]
        self.net_lock.release()

    def service_resolved(self, interface, protocol, name, type, domain, host, aprotocol, address, port, txts, flags):
        if not (flags & avahi.LOOKUP_RESULT_LOCAL):
            self.net_lock.acquire()
            if name not in self.net_services:
                prot = socket.AF_INET
                if protocol == avahi.PROTO_INET6:
                    prot = socket.AF_INET6
                self.net_services[name] = (address, port, prot)
            self.net_lock.release()

        publish = False
        for t in txts:
            s = "".join(chr(b) for b in t)
            match = re.search("host=(.+),mac=(.+)", s)
            host = match.group(1)
            mac = match.group(2)
            if match and host:
                if self.host_service.Add(host, mac):
                    publish = True
        if publish:
            self.host_service.Publish()

    def get_net_services(self):
        self.net_lock.acquire()
        net_services = self.net_services.copy()
        self.net_lock.release()
        return net_services


class HostWakeupService(dbus.service.Object):
    def __init__(self, bus, avahi_service, interface):
        bus_name = dbus.service.BusName(dbus_interface, bus = bus)
        dbus.service.Object.__init__(self, bus_name, "/Hosts")
        self.Hosts = {}
        self.avahi_service = avahi_service
        self.interface = interface

    def SetAvahiBrowser(self, avahi_browser):
        self.avahi_browser = avahi_browser

    def CallTcpServer(self, address, port, protocol, message):
        print "calling %s:%d: %s" % (address, port, message)
        sock = socket.socket(protocol, socket.SOCK_STREAM)
        sock.connect((address, port))
        try:
            sock.sendall(message)
        finally:
            sock.close()

    @dbus.service.method(dbus_interface, in_signature = "s", out_signature = "b")
    def Wakeup(self, host):
        if self.InternWakeup(host):
            return True
        if self.avahi_browser:
            net_services = self.avahi_browser.get_net_services()
            for name in net_services:
                (address, port, protocol) = net_services[name]
                self.CallTcpServer(address, port, protocol, "wakeup %s" % (host))
        return False

    def InternWakeup(self, host):
        if not host:
            return False
        lowerHost = host.lower()
        if lowerHost not in self.Hosts:
            return False
        broadcast = get_broadcast_addr(self.interface)
        if not broadcast:
            return False
        print "wake up " + host + " with MAC " + self.Hosts[lowerHost] + " on broadcast address " + broadcast
        wake_on_lan(self.Hosts[lowerHost], broadcast)
        return True

    @dbus.service.method(dbus_interface, in_signature = "ss", out_signature = "b")
    def Add(self, host, mac):
        if not host or not mac:
            return False
        lowerHost = host.lower().encode("ascii", "ignore")
        lowerMac = mac.lower().encode("ascii", "ignore")
        if (lowerHost in self.Hosts) and (self.Hosts[lowerHost] == lowerMac):
            return False
        print "add host %s with mac %s" % (lowerHost, lowerMac)
        self.Hosts[lowerHost] = lowerMac
        return True

    @dbus.service.method(dbus_interface, in_signature = "s", out_signature = "b")
    def Remove(self, host):
        if not host:
            return False
        lowerHost = host.lower().encode("ascii", "ignore")
        if lowerHost not in self.Hosts:
            return False
        print "remove host %s" % (lowerHost)
        del self.Hosts[lowerHost]
        return True

    @dbus.service.method(dbus_interface, in_signature = "", out_signature = "b")
    def Publish(self):
        txts = []
        for host in self.Hosts:
            txt = "host=%s,mac=%s" % (host, self.Hosts[host])
            print "publish: " + txt
            txts.append(txt)
        self.avahi_service.Publish(txts)
        return True


# http://docs.python.org/2/library/socketserver.html
class TcpServerRequestHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        data = self.rfile.readline().strip().lower()
        print "recv: " + data
        if data.startswith("wakeup "):
            host = data[7:].strip()
            if hostWakeupService.InternWakeup(host):
                self.wfile.write("wakeup " + host)
            else:
                self.wfile.write("unknown host " + host)
        else:
            self.wfile.write("unknown command " + data)


class TcpServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


def StartTcpServer(host):
    server = TcpServer((host, 0), TcpServerRequestHandler)
    ip, port = server.server_address
    serverThread = threading.Thread(target = server.serve_forever)
    serverThread.daemon = True
    serverThread.start()
    return (server, serverThread, port)

def StopTcpServer(server):
    if server:
        server.shutdown()


def sig_term_handler(signum, frame):
    if signum == signal.SIGTERM:
        print "TERM: quitting"
        if not loop:
            sys.exit(0)
        else:
            loop.quit()

def parse_args(argv):
    try:
        opts, args = getopt.getopt(argv, "i:f:", ["interface", "file"])
    except getopt.GetoptError:
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-i", "--interface"):
            global mac_interface
            mac_interface = arg
            print "using interface " + mac_interface
        elif opt in ("-f", "--file"):
            global host_file
            host_file = arg
            print "using host file " + host_file


if __name__ == "__main__":
    gobject.threads_init()
    signal.signal(signal.SIGTERM, sig_term_handler)
    parse_args(sys.argv[1:])

    if not mac_interface in netifaces.interfaces():
        print "interface " + mac_interface + " not found"
        sys.exit(1)

    bus = dbus.SystemBus(mainloop = DBusGMainLoop())
    loop = gobject.MainLoop()

    hostname = socket.gethostname().lower()
    mac = get_mac(mac_interface)
    print "host " + hostname + " has MAC " + mac + " on interface " + mac_interface

    (tcpServer, tcpThread, tcpPort) = StartTcpServer("")
    if tcpPort != 0:
        print "listening on port %d" % (tcpPort)

    avahi_server = dbus.Interface(bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER), avahi.DBUS_INTERFACE_SERVER)
    avahiService = AvahiService(avahi_server, "host-wakeup on " + hostname, service_type, tcpPort)

    hostWakeupService = HostWakeupService(bus, avahiService, mac_interface)
    hostWakeupService.Add(hostname, mac)

    print "reading hosts from " + host_file
    hosts = read_hosts(host_file)
    for h in hosts:
        hostWakeupService.Add(h, hosts[h])

    hostWakeupService.Publish()
    avahiBrowser = AvahiBrowser(avahi_server, hostWakeupService, avahi.PROTO_INET, service_type)
    hostWakeupService.SetAvahiBrowser(avahiBrowser)
    try:
        loop.run()
    except:
        pass
    StopTcpServer(tcpServer)
    write_hosts(host_file, hostWakeupService.Hosts)
