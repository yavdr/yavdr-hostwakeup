#!/usr/bin/python3

import avahi
import dbus
import dbus.service
import netifaces
import optparse
import os
import signal
import re
import socket
import socketserver
import struct
import sys
import threading
from collections import namedtuple
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GObject

service_type = "_host-wakeup._tcp"
dbus_interface = "de.yavdr.hostwakeup"
host_file = "/var/cache/hostwakeup/hosts.conf"


class Hostwakeup:
    def __init__(self, options):
        self.host_file = options.host_file
        self.default_interface = options.interface
        self.hostname = socket.gethostname().lower()
        self.interfaces = self.get_interfaces()
        self.hosts = self.read_hosts()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.write_hosts()

    def get_interfaces(self):
        interfaces = []
        Interface = namedtuple('Interface', ['name', 'broadcast_addr', 'mac'])
        if_list = ([self.default_interface] if self.default_interface
                   else netifaces.interfaces())

        for interf in if_list:
            if self.get_broadcast(interf):
                interface = Interface(name=interf,
                                      broadcast_addr=self.get_broadcast(interf),
                                      mac=self.get_mac(interf))
                print("add interface {} with mac {} and broadcast {}".format(
                    interf, self.get_broadcast(interf), self.get_mac(interf)))
                interfaces.append(interface)
        return interfaces

    def read_hosts(self):
        hosts = {}
        try:
            with open(self.host_file, "r") as f:
                for line in f:
                    line = line.rstrip("\n").strip()
                    match = re.search("host=(.+),mac=(.+)", line)
                    host = match.group(1)
                    mac = match.group(2)
                    if match and host:
                        hosts[host.lower()] = mac.lower()
        except OSError as e:
            print("Error opening {}:".format(self.host_file),
                  os.strerror(e.errno))
        except Exception as e:
            print(e)
        finally:
            return hosts

    def write_hosts(self):
        try:
            if not hostWakeupService.Hosts:
                os.remove(self.host_file)
            else:
                with open(self.host_file, "w") as f:
                    for host, mac in hostWakeupService.Hosts.items():
                        f.write("host={},mac={}\n".format(host, mac))
        except OSError as e:
            print("Error changing {}:".format(self.host_file),
                  os.strerror(e.errno))
        except Exception as e:
            print(e)

    @classmethod
    def get_mac(self, interface):
        if_dict = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]
        return if_dict["addr"].lower() if "addr" in if_dict else None

    @classmethod
    def get_broadcast(self, interface):
        if_dict = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
        if "broadcast" in if_dict:
            return if_dict["broadcast"]
        else:
            if_dict = netifaces.ifaddresses(interface)[netifaces.AF_INET6][0]
            if "broadcast" in if_dict:
                return "ff02::1"
            else:
                return None


class AvahiService:
    def __init__(self, avahi_server, name, type, port, *subtypes):
        self.server = avahi_server
        self.name = name
        self.serviceType = type
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
            self.group.AddService(avahi.IF_UNSPEC,
                                  avahi.PROTO_UNSPEC,
                                  dbus.UInt32(0),
                                  self.name, self.serviceType, "", "",
                                  dbus.UInt16(self.port),
                                  avahi.string_array_to_txt_array(txts))
            for subtype in self.subtypes:
                if not subtype.endswith("._sub." + self.serviceType):
                    subtype = subtype + "._sub." + self.serviceType
                self.group.AddServiceSubtype(avahi.IF_UNSPEC,
                                             avahi.PROTO_UNSPEC,
                                             dbus.UInt32(0),
                                             self.name,
                                             self.serviceType, "",
                                             subtype)
            self.group.Commit()


class AvahiBrowser:
    def __init__(self, avahi_server, host_service, protocol, type):
        self.avahi_server = avahi_server
        self.host_service = host_service
        self.net_lock = threading.Lock()
        self.net_services = {}
        b = avahi_server.ServiceBrowserNew(avahi.IF_UNSPEC, protocol, type, "",
                                           dbus.UInt32(0))
        self.browser = dbus.Interface(bus.get_object(avahi.DBUS_NAME, b),
                                      avahi.DBUS_INTERFACE_SERVICE_BROWSER)
        self.browser.connect_to_signal("ItemNew", self.new_handler,
                                       byte_arrays=True)
        self.browser.connect_to_signal("ItemRemove", self.remove_handler,
                                       byte_arrays=True)

    def new_handler(self, interface, protocol, name, type, domain, flags):
        r = self.avahi_server.ServiceResolverNew(
            interface, protocol, name, type, domain, avahi.PROTO_UNSPEC,
            dbus.UInt32(0), byte_arrays=True)
        self.resolver = dbus.Interface(bus.get_object(avahi.DBUS_NAME, r),
                                       avahi.DBUS_INTERFACE_SERVICE_RESOLVER)
        self.resolver.connect_to_signal("Found", self.service_resolved,
                                        byte_arrays=True)

    def remove_handler(self, interface, protocol, name, type, domain, flags):
        self.net_lock.acquire()
        if name in self.net_services:
            del self.net_services[name]
        self.net_lock.release()

    def service_resolved(self, interface, protocol, name, type, domain, host,
                         aprotocol, address, port, txts, flags):
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
            match = re.search("host=(.+),mac=(.+)", t.decode())
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
    def __init__(self, bus, avahi_service, interfaces):
        bus_name = dbus.service.BusName(dbus_interface, bus=bus)
        dbus.service.Object.__init__(self, bus_name, "/Hosts")
        self.host_lock = threading.Lock()
        self.Hosts = {}
        self.avahi_service = avahi_service
        self.interfaces = interfaces

    def SetAvahiBrowser(self, avahi_browser):
        self.avahi_browser = avahi_browser

    def CallTcpServer(self, address, port, protocol, message):
        print("calling {0}:{1}: {2}".format(address, port, message))
        sock = socket.socket(protocol, socket.SOCK_STREAM)
        sock.connect((address, port))
        try:
            sock.sendall(message.encode())
        finally:
            sock.close()

    @dbus.service.method(dbus_interface, in_signature="s", out_signature="b")
    def Wakeup(self, host):
        if self.InternWakeup(host):
            return True
        if self.avahi_browser:
            net_services = self.avahi_browser.get_net_services()
            for name in net_services:
                address, port, protocol = net_services[name]
                self.CallTcpServer(address, port, protocol,
                                   "wakeup {0}".format(host))
        return False

    def InternWakeup(self, host):
        if not host:
            return False
        lowerHost = host.lower()
        self.host_lock.acquire()
        if lowerHost not in self.Hosts:
            self.host_lock.release()
            return False
        for interface in self.interfaces:
            broadcast = interface.broadcast_addr
            print("wake up {} with MAC {} on broadcast address {}".format(
                host, self.Hosts[lowerHost], broadcast))
            self.wake_on_lan(self.Hosts[lowerHost], broadcast)
        self.host_lock.release()
        return True

    @classmethod
    def wake_on_lan(self, macaddress, broadcast):
        if len(macaddress) == 12:
            pass
        elif len(macaddress) == 12 + 5:
            sep = macaddress[2]
            macaddress = macaddress.replace(sep, "")
        else:
            raise ValueError("incorrect MAC address format")
        data = b"FFFFFFFFFFFF" + (macaddress * 20).encode()
        send_data = b""
        for i in range(0, len(data), 2):
            send_data += struct.pack("B", int(data[i: i + 2], 16))
        family, socktype, proto, _, _ = socket.getaddrinfo(
            broadcast, 7, proto=socket.SO_BROADCAST)[0]
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, proto, 1)
        sock.sendto(send_data, (broadcast, 7))

    @dbus.service.method(dbus_interface, in_signature="ss", out_signature="b")
    def Add(self, host, mac):
        if not all((host, mac)):
            return False
        lowerHost = host.lower()
        lowerMac = mac.lower()
        self.host_lock.acquire()
        if (lowerHost in self.Hosts) and (self.Hosts[lowerHost] == lowerMac):
            self.host_lock.release()
            return False
        print("add host {0} with mac {1}".format(lowerHost, lowerMac))
        self.Hosts[lowerHost] = lowerMac
        self.host_lock.release()
        return True

    @dbus.service.method(dbus_interface, in_signature="s", out_signature="b")
    def Remove(self, host):
        if not host:
            return False
        lowerHost = host.lower().encode("ascii", "ignore")
        self.host_lock.acquire()
        if lowerHost not in self.Hosts:
            self.host_lock.release()
            return False
        print("remove host {0}".format(lowerHost))
        del self.Hosts[lowerHost]
        self.host_lock.release()
        return True

    @dbus.service.method(dbus_interface, in_signature="", out_signature="as")
    def List(self):
        hosts = []
        self.host_lock.acquire()
        for host in self.Hosts:
            hosts.append(host)
        self.host_lock.release()
        return hosts

    @dbus.service.method(dbus_interface, in_signature="", out_signature="b")
    def Publish(self):
        txts = []
        self.host_lock.acquire()
        for host in self.Hosts:
            txt = "host={0},mac={1}".format(host, self.Hosts[host])
            print("publish: " + txt)
            txts.append(txt)
        self.host_lock.release()
        self.avahi_service.Publish(txts)
        return True


# http://docs.python.org/2/library/socketserver.html
class TcpServerRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        data = self.rfile.readline().strip().lower()
        print("recv: " + data)
        if data.startswith("wakeup "):
            host = data[7:].strip()
            if hostWakeupService.InternWakeup(host):
                self.wfile.write("wakeup " + host)
            else:
                self.wfile.write("unknown host " + host)
        else:
            self.wfile.write("unknown command " + data)


class TcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, host):
        super().__init__((host, 0), TcpServerRequestHandler)
        self.tcpPort = self.server_address[1]
        self.serverThread = threading.Thread(target=self.serve_forever)
        self.serverThread.daemon = True

    def __enter__(self):
        self.serverThread.start()
        return self

    def __exit__(self, type, value, traceback):
        self.shutdown()


def sig_term_handler(signum, frame):
    print("got signal:", signum)
    if signum == signal.SIGTERM:
        print("TERM: quitting")
        if not loop:
            sys.exit(0)
        else:
            loop.quit()


if __name__ == "__main__":
    GObject.threads_init()
    bus = dbus.SystemBus(mainloop=DBusGMainLoop())
    loop = GObject.MainLoop()
    hostWakeupService = None
    signal.signal(signal.SIGTERM, sig_term_handler)
    parser = optparse.OptionParser()
    parser.add_option("-f", "--host_file",
                      dest="host_file", help="store known hosts in this file")
    parser.add_option("-i", "--interface",
                      dest="interface", default=None,
                      help="use data for this interface, e.g. eth0")
    options, args = parser.parse_args()
    with Hostwakeup(options) as hostwakeup:
        avahi_service_name = "host-wakeup on {}".format(hostwakeup.hostname)

        with TcpServer("") as tcpserver:
            if tcpserver.tcpPort != 0:
                print("listening on port {0}".format(tcpserver.tcpPort))
            avahi_server = dbus.Interface(bus.get_object(
                avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER),
                avahi.DBUS_INTERFACE_SERVER)
            avahiService = AvahiService(avahi_server,
                                        avahi_service_name,
                                        service_type, tcpserver.tcpPort)
            hostWakeupService = HostWakeupService(bus, avahiService,
                                                  hostwakeup.interfaces)
            for interface in hostwakeup.interfaces:
                print("host {} has MAC {} on interface {}".format(
                    hostwakeup.hostname, interface.mac, interface.name))
                hostWakeupService.Add(hostwakeup.hostname, interface.mac)

            for host, mac in hostwakeup.hosts.items():
                hostWakeupService.Add(host, mac)

            hostWakeupService.Publish()
            avahiBrowser = AvahiBrowser(avahi_server,
                                        hostWakeupService,
                                        avahi.PROTO_INET, service_type)
            hostWakeupService.SetAvahiBrowser(avahiBrowser)
        try:
            loop.run()
        except KeyboardInterrupt:
            print("Good Bye!")
        except Exception as e:
            loop.quit()
            sys.exit(e)
