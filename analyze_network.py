from mac_vendor_lookup import MacLookup
from scapy.all import ICMP, IP, Ether, Raw, rdpcap

UNKNOWN = "Unknown"


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.packets = rdpcap(pcap_path)
        self.mac_vendor_lookup = MacLookup()
        self.initialize_dicts()

    def initialize_dicts(self):
        self.packets_from_ip = dict()
        self.packets_from_mac = dict()
        self.packets_to_ip = dict()
        self.packets_to_mac = dict()
        for packet in self.packets:
            if Ether in packet:
                mac_src = packet[Ether].src
                if mac_src not in self.packets_from_mac:
                    self.packets_from_mac[mac_src] = []
                self.packets_from_mac[mac_src].append(packet)

                mac_dst = packet[Ether].dst
                if mac_dst not in self.packets_to_mac:
                    self.packets_to_mac[mac_dst] = []
                self.packets_to_mac[mac_dst].append(packet)
            if IP in packet:
                ip_src = packet[IP].src
                if ip_src not in self.packets_from_ip:
                    self.packets_from_ip[ip_src] = []
                self.packets_from_ip[ip_src].append(packet)

                ip_dst = packet[IP].dst
                if ip_dst not in self.packets_to_ip:
                    self.packets_to_ip[ip_dst] = []
                self.packets_to_ip[ip_dst].append(packet)

    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        all_ips = set(self.packets_from_ip.keys()) | set(self.packets_to_ip.keys())
        return list(all_ips)

    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        all_macs = set(self.packets_from_mac.keys()) | set(self.packets_to_mac.keys())
        return list(all_macs)

    def _get_info_by_packets(self, packets):
        """returns a dict with all information about the device in given packets"""
        info = dict()
        info["MAC"] = UNKNOWN
        info["IP"] = UNKNOWN
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
                    ip_unknown = True

        if info["MAC"] != UNKNOWN:
            mac = info["MAC"]
            info["Packets sent from MAC"] = (
                len(self.packets_from_mac[mac]) if mac in self.packets_from_mac else 0
            )
            info["Packets sent to MAC"] = (
                len(self.packets_to_mac[mac]) if mac in self.packets_to_mac else 0
            )
        info["HTTP DATA"] = UNKNOWN
        if info["IP"] != UNKNOWN:
            ip = info["IP"]
            info["Packets sent from IP"] = (
                len(self.packets_from_ip[ip]) if ip in self.packets_from_ip else 0
            )
            info["Packets sent to IP"] = (
                len(self.packets_to_ip[ip]) if ip in self.packets_to_ip else 0
            )
            for packet in self.packets_from_ip[info["IP"]]:
                if Raw in packet and b"HTTP" in packet[Raw].load:
                    raw_data = packet[Raw].load
                    header_data = raw_data[raw_data.find(b"\r\n") + 2 :]
                    info["HTTP DATA"] = dict()
                    for header in header_data.split(b"\r\n")[:-2]:
                        name, value = (
                            header[: header.find(b":")].decode(),
                            header[header.find(b":") + 2 :].decode(),
                        )
                        info["HTTP DATA"][name] = value
        try:
            info["VENDOR"] = self.mac_vendor_lookup.lookup(info["MAC"])
        except:
            info["VENDOR"] = UNKNOWN

        info["OS"] = self.guess_os(info)
        return info

    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        return self._get_info_by_packets(self.packets_from_mac[mac])

    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        return self._get_info_by_packets(self.packets_from_ip[ip])

    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        return [self.get_info_by_mac(mac) for mac in self.packets_from_mac]

    def guess_os(self, device_info):
        if device_info["MAC"] == UNKNOWN:
            return UNKNOWN
        possible_OS = []
        for packet in self.packets_from_mac[device_info["MAC"]]:
            if ICMP in packet and Raw in packet:
                raw_data = packet[Raw].load
                if self._is_macOS_icmp_raw(raw_data):
                    possible_OS.append("macOS")
                if self._is_linux_icmp_raw(raw_data):
                    possible_OS.append("linux")
                if self._is_windows_icmp_raw(raw_data):
                    possible_OS.append("windows")

        match len(possible_OS):
            case 0:
                return UNKNOWN
            case 1:
                return possible_OS[0]
            case _:
                return possible_OS

    def _is_macOS_icmp_raw(self, raw_data):
        for i in range(8, len(raw_data)):
            if raw_data[i] != i % 256:
                return False
        return True

    def _is_linux_icmp_raw(self, raw_data):
        for i in range(16, len(raw_data)):
            if raw_data[i] != i % 256:
                return False
        return True

    def _is_windows_icmp_raw(self, raw_data):
        for i in range(len(raw_data)):
            if raw_data[i] != ord("a") + i % 23:
                return False
        return True

    def __repr__(self):
        return f"Network Analyzer(Path:{self.pcap_path},Packets:{len(self.packets)})"

    def __str__(self):
        return f"Network Analyzer(Path:{self.pcap_path},Packets:{len(self.packets)})"


if __name__ == "__main__":
    network_analyzer = AnalyzeNetwork(
        r"C:\Users\eli\Documents\Arazim\Hive\Q@\Guess Who\pcap-03.pcapng"
    )
    print(network_analyzer.get_info())
