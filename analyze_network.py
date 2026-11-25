from scapy.all import rdpcap, IP, Ether
from mac_vendor_lookup import MacLookup

UNKNOWN = "Unknown"


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.packets = rdpcap(pcap_path)
        self.mac_vendor_lookup = MacLookup()

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        IP_set = set()
        for packet in self.packets:
            if IP in packet:
                IP_set.add(packet[IP].src)
                IP_set.add(packet[IP].dst)
        return list(IP_set)

    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        MAC_set = set()
        for packet in self.packets:
            if Ether in packet:
                MAC_set.add(packet[Ether].src)
                MAC_set.add(packet[Ether].dst)
        return list(MAC_set)

    def _get_info_by_packets(self, packets):
        """returns a dict with all information about the device in given packets"""
        info = {"MAC": UNKNOWN, "IP": UNKNOWN}
        mac_unknown = False
        ip_unknown = False
        for packet in packets:
            if not mac_unknown and info["MAC"] == UNKNOWN:
                info["MAC"] = packet[Ether].src
            elif info["MAC"] != packet[Ether].src:
                info["MAC"] = UNKNOWN
                mac_unknown = True
            if IP in packet:
                if not ip_unknown and info["IP"] == UNKNOWN:
                    info["IP"] = packet["IP"].src
                elif info["IP"] != packet[IP].src:
                    info["IP"] = UNKNOWN
                    mac_unknown = True
        try:
            info["VENDOR"] = self.mac_vendor_lookup.lookup(info["MAC"])
        except:
            info["VENDOR"] = UNKNOWN
        return info

    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        relevant_packets = [
            packet
            for packet in self.packets
            if Ether in packet and packet[Ether].src == mac
        ]
        return self._get_info_by_packets(relevant_packets)

    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        relevant_packets = [
            packet for packet in self.packets if IP in packet and packet[IP].src == ip
        ]
        return self._get_info_by_packets(relevant_packets)

    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        macs = self.get_macs()
        return [self.get_info_by_mac(mac) for mac in macs]

    def __repr__(self):
        return f"Network Analyzer(Path:{self.pcap_path},Packets:{len(self.packets)})"

    def __str__(self):
        return f"Network Analyzer(Path:{self.pcap_path},Packets:{len(self.packets)})"


if __name__ == "__main__":
    network_analyzer = AnalyzeNetwork(
        r"C:\Users\eli\Documents\Arazim\Hive\Q@\Guess Who\pcap-00.pcapng"
    )
    print(network_analyzer.get_info())
