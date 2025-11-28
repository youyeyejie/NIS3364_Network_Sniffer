from tkinter import messagebox
from typing import Dict, Any
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, _ICMPv6 as ICMPv6

# from sniffer import NetworkSniffer
  
def get_port_name(port, protocol):
    """获取端口对应的服务名称"""
    # 常见端口与服务名称映射
    common_ports = {
        # TCP端口
        "TCP": {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
            993: "IMAPS", 995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        },
        # UDP端口
        "UDP": {
            53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
            123: "NTP", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP",
            514: "Syslog", 520: "RIP", 1900: "SSDP", 5353: "mDNS",
            5355: "LLMNR"
        }
    }
    
    if protocol in common_ports and port in common_ports[protocol]:
        return common_ports[protocol][port]
    return None


def process_ether(packet: scapy.Packet, packet_info: Dict[str, Any]):
    """处理以太网帧"""
    if Ether not in packet:
        return

    ether_protocol_names = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x0801: "ICMP",
        0x0802: "IGMP",
        0x0803: "IPX",
        0x0804: "XNS",
        0x0805: "TCP",
        0x0806: "UDP",
        0x0807: "OSPF",
        0x0808: "EIGRP",
        0x0809: "BGP",
        0x080A: "NTP",
        0x080B: "SNMP",
        0x080C: "Syslog",
        0x080D: "TFTP",
        0x080E: "DHCP",
        0x080F: "TFTP",
    }
    ether_protocol_name = ether_protocol_names.get(packet[Ether].type, "未知")
    packet_info["src"] = packet[Ether].src.upper()
    packet_info["dst"] = packet[Ether].dst.upper()
    packet_info["protocol"] = "Ether"
    packet_info["info"] = f"Ether {packet[Ether].type} {packet_info['src']} -> {packet_info['dst']}"
    packet_info["detail"] += f"=== 以太网层 ===\n"
    packet_info["detail"] += f"源 MAC: {packet_info['src']}\n"
    packet_info["detail"] += f"目的 MAC: {packet_info['dst']}\n"
    packet_info["detail"] += f"类型: 0x{packet[Ether].type:04x} ({ether_protocol_name})\n"
    packet_info["detail"] += f"载荷长度: {len(packet[Ether].payload)} 字节\n\n"

    # 尝试提取应用层数据
    if packet.haslayer(scapy.Raw):
        packet_info["data"] = packet[scapy.Raw].load 

def process_arp(packet: scapy.Packet, packet_info: Dict[str, Any]):
    """处理ARP层"""
    if ARP not in packet:
        return

    arp_packet = packet[ARP]
    packet_info["protocol"] = "ARP"
    
    # 获取ARP操作类型的易读名称
    arp_op_names = {
        1: "ARP 请求 (Who-has)",
        2: "ARP 响应 (Is-at)",
        3: "RARP 请求",
        4: "RARP 响应",
        5: "DRARP 请求",
        6: "DRARP 响应",
        7: "DRARP 错误",
        8: "InARP 请求",
        9: "InARP 响应"
    }
    arp_op_name = arp_op_names.get(arp_packet.op, f"未知操作 ({arp_packet.op})")
    
    # 构建信息摘要
    if arp_packet.op == 1:  # 请求
        packet_info["info"] = f"{arp_op_name} {arp_packet.psrc}? 告诉 {arp_packet.pdst}"
    elif arp_packet.op == 2:  # 响应
        packet_info["info"] = f"{arp_op_name} {arp_packet.psrc} 是 {arp_packet.hwsrc}"
    elif arp_packet.op == 3:  # RARP 请求
        packet_info["info"] = f"{arp_op_name} {arp_packet.hwsrc}? 告诉 {arp_packet.psrc}"
    elif arp_packet.op == 4:  # RARP 响应
        packet_info["info"] = f"{arp_op_name} {arp_packet.hwsrc} 是 {arp_packet.psrc}"
    else:
        packet_info["info"] = f"ARP {arp_op_name} {arp_packet.psrc} -> {arp_packet.pdst}"
    
    arp_hwtype_names = {
        1: "以太网",
        2: "令牌环",
        3: "ARCNET",
        4: "HDLC",
        5: "FDDI"
    }
    arp_hwtype_name = arp_hwtype_names.get(arp_packet.hwtype, f"未知硬件类型 ({arp_packet.hwtype})")

    arp_ptype_names = {
        0x0800: "IPv4",
        0x0801: "IPv4 路由",
        0x0802: "IPv4 组播",
        0x0803: "IPv4 分片",
        0x0804: "IPv4 选项",
        0x0805: "IPv4 时间戳",
        0x0806: "ARP",
        0x8035: "RARP",
        0x809B: "DRARP",
        0x80F3: "InARP",
    }
    arp_ptype_name = arp_ptype_names.get(arp_packet.ptype, f"未知协议类型 ({arp_packet.ptype})")

    # 详细信息
    packet_info["detail"] += f"=== ARP 层 ===\n"
    packet_info["detail"] += f"硬件类型: {arp_packet.hwtype} ({arp_hwtype_name})\n"
    packet_info["detail"] += f"协议类型: 0x{arp_packet.ptype:04x} ({arp_ptype_name})\n"
    packet_info["detail"] += f"硬件地址长度: {arp_packet.hwlen} 字节\n"
    packet_info["detail"] += f"协议地址长度: {arp_packet.plen} 字节\n"
    packet_info["detail"] += f"操作类型: {arp_packet.op} ({arp_op_name})\n"
    packet_info["detail"] += f"发送方硬件地址: {arp_packet.hwsrc}\n"
    packet_info["detail"] += f"发送方IP地址: {arp_packet.psrc}\n"
    packet_info["detail"] += f"目标硬件地址: {arp_packet.hwdst}\n"
    packet_info["detail"] += f"目标IP地址: {arp_packet.pdst}\n"
    packet_info["detail"] += f"载荷长度: {len(arp_packet.payload)} 字节\n\n"

    # 尝试提取应用层数据
    if packet.haslayer(scapy.Raw):
        packet_info["data"] = packet[scapy.Raw].load

def process_ip(packet: scapy.Packet, packet_info: Dict[str, Any]):
    """处理IP层"""
    if IP not in packet:
        return

    ip_packet = packet[IP]
    # 获取协议类型名称
    IP_proto_names = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        58: "ICMPv6",
        89: "OSPF",
        103: "PIM",
        112: "VRRP",
        132: "SCTP",
        133: "MPLS-in-IP",
        134: "IPv6",
        135: "IPv6-route",
        136: "IPv6-frag",
        137: "IPv6-auth",
        138: "IPv6-encap",
        139: "IPv6-icmp",
        140: "IPv6-nonxt",
        141: "IPv6-opts",
    }
    IP_proto_name = IP_proto_names.get(ip_packet.proto, f"Protocol {ip_packet.proto}")

    # 检查是否是分片数据包
    is_fragment = (not ip_packet.flags.DF) and (ip_packet.flags.MF or ip_packet.frag > 0)
    if is_fragment:
        packet_info["is_fragment"] = "1"
    
    packet_info["protocol"] = "IP"
    packet_info["info"] = f"IP {ip_packet.src} -> {ip_packet.dst} TTL={ip_packet.ttl}"
    
    packet_info["src"] = ip_packet.src
    packet_info["dst"] = ip_packet.dst
    
    # 详细信息
    packet_info["detail"] += f"=== IPv4 层 ===\n"
    packet_info["detail"] += f"版本: {ip_packet.version}\n"
    packet_info["detail"] += f"头部长度: {ip_packet.ihl * 4} 字节\n"
    packet_info["detail"] += f"服务类型: {ip_packet.tos}\n"
    packet_info["detail"] += f"数据包总长度: {ip_packet.len} 字节\n"
    packet_info["detail"] += f"数据包标识: {ip_packet.id}\n"
    packet_info["detail"] += f"分片标志: \n"
    packet_info["detail"] += f"  - DF: {ip_packet.flags.DF}\n"
    packet_info["detail"] += f"  - MF: {ip_packet.flags.MF}\n"
    packet_info["detail"] += f"分片偏移: {ip_packet.frag} (字节偏移: {ip_packet.frag * 8})\n"
    packet_info["detail"] += f"生存时间: {ip_packet.ttl}\n"
    packet_info["detail"] += f"上层协议: {ip_packet.proto} ({IP_proto_name})\n"
    packet_info["detail"] += f"校验和: 0x{ip_packet.chksum:04x}\n"
    packet_info["detail"] += f"源IP: {ip_packet.src}\n"
    packet_info["detail"] += f"目的IP: {ip_packet.dst}\n"
    packet_info["detail"] += f"IP选项: {ip_packet.options}\n\n"

    # 尝试提取应用层数据
    if packet.haslayer(scapy.Raw):
        packet_info["data"] = packet[scapy.Raw].load

def process_ipv6(packet: scapy.Packet, packet_info: Dict[str, Any]):
    """处理IPv6层"""
    if IPv6 not in packet:
        return

    ipv6_packet = packet[IPv6]
    packet_info["protocol"] = "IPv6"
    packet_info["src"] = ipv6_packet.src
    packet_info["dst"] = ipv6_packet.dst
    
    # 获取下一个头字段对应的协议名称
    IPv6_proto_names = {
        0: "HOPOPT",
        1: "ICMPv6",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        58: "ICMPv6",
        60: "IPv6-route",
        61: "IPv6-frag",
        62: "IPv6-auth",
        63: "IPv6-encap",
        64: "IPv6-icmp",
        65: "IPv6-nonxt",
        66: "IPv6-opts",
    }
    IPv6_proto_name = IPv6_proto_names.get(ipv6_packet.nh, f"Protocol {ipv6_packet.nh}")
    
    packet_info["info"] = f"IPv6 {ipv6_packet.src} -> {ipv6_packet.dst} hlim={ipv6_packet.hlim}"
    
    # 详细信息
    packet_info["detail"] += f"=== IPv6 层 ===\n"
    packet_info["detail"] += f"版本: {ipv6_packet.version}\n"
    packet_info["detail"] += f"流量类别: {ipv6_packet.tc}\n"
    packet_info["detail"] += f"流标签: 0x{ipv6_packet.fl:08x}\n"
    packet_info["detail"] += f"载荷长度: {ipv6_packet.plen} 字节\n"
    packet_info["detail"] += f"上层协议: {ipv6_packet.nh} ({IPv6_proto_name})\n"
    packet_info["detail"] += f"跳数限制: {ipv6_packet.hlim}\n"
    packet_info["detail"] += f"源IPv6地址: {ipv6_packet.src}\n"
    packet_info["detail"] += f"目的IPv6地址: {ipv6_packet.dst}\n\n"

    # 尝试提取应用层数据
    if packet.haslayer(scapy.Raw):
        packet_info["data"] = packet[scapy.Raw].load

def process_icmp(packet: scapy.Packet, packet_info: Dict[str, Any]):
    """处理ICMP层"""
    if ICMP not in packet:
        return
    icmp_packet = packet[ICMP]
    packet_info["protocol"] = "ICMP"
    packet_info["src_port"] = "ICMP"
    packet_info["dst_port"] = "ICMP"
    
    # ICMP类型名称映射
    icmp_types = {
        0: "回显响应 (Echo Reply)",
        3: "目标不可达 (Destination Unreachable)",
        4: "源抑制 (Source Quench)",
        5: "重定向 (Redirect)",
        8: "回显请求 (Echo Request)",
        9: "路由器通告 (Router Advertisement)",
        10: "路由器请求 (Router Solicitation)",
        11: "超时 (Time Exceeded)",
        12: "参数问题 (Parameter Problem)",
        13: "时间戳请求 (Timestamp Request)",
        14: "时间戳响应 (Timestamp Reply)",
        17: "地址掩码请求 (Address Mask Request)",
        18: "地址掩码响应 (Address Mask Reply)"
    }
    icmp_type_name = icmp_types.get(icmp_packet.type, f"未知类型 ({icmp_packet.type})")
    
    # 根据类型构建信息摘要
    if icmp_packet.type == 8:  # Echo Request
        packet_info["info"] = f"ICMP {icmp_type_name} (Type={icmp_packet.type}, Code={icmp_packet.code})"
        if hasattr(icmp_packet, 'seq') and hasattr(icmp_packet, 'id'):
            packet_info["info"] += f" ID={icmp_packet.id} Seq={icmp_packet.seq}"
    elif icmp_packet.type == 0:  # Echo Reply
        packet_info["info"] = f"ICMP {icmp_type_name} (Type={icmp_packet.type}, Code={icmp_packet.code})"
        if hasattr(icmp_packet, 'seq') and hasattr(icmp_packet, 'id'):
            packet_info["info"] += f" ID={icmp_packet.id} Seq={icmp_packet.seq}"
    elif icmp_packet.type == 3:  # Destination Unreachable
        dest_unreachable_codes = {
            0: "网络不可达",
            1: "主机不可达",
            2: "协议不可达",
            3: "端口不可达",
            4: "需要分片但设置了不分片位",
            5: "源路由失败",
            6: "目的网络未知",
            7: "目的主机未知",
            8: "源主机被隔离",
            9: "用于目的网络的通信被禁止",
            10: "用于目的主机的通信被禁止",
            11: "对请求的服务类型，网络不可达",
            12: "对请求的服务类型，主机不可达"
        }
        code_name = dest_unreachable_codes.get(icmp_packet.code, f"未知代码 ({icmp_packet.code})")
        packet_info["info"] = f"ICMP {icmp_type_name}: {code_name}"
    elif icmp_packet.type == 11:  # Time Exceeded
        time_exceeded_codes = {
            0: "跳数超过",
            1: "分片 reassembly 超时"
        }
        code_name = time_exceeded_codes.get(icmp_packet.code, f"未知代码 ({icmp_packet.code})")
        packet_info["info"] = f"ICMP {icmp_type_name}: {code_name}"
    else:
        packet_info["info"] = f"ICMP {icmp_type_name} (Type={icmp_packet.type}, Code={icmp_packet.code})"
    
    # 详细信息
    packet_info["detail"] += f"=== ICMP 层 ===\n"
    packet_info["detail"] += f"类型: {icmp_packet.type} ({icmp_type_name})\n"
    packet_info["detail"] += f"类型代码: {icmp_packet.code}\n"
    packet_info["detail"] += f"校验和: 0x{icmp_packet.chksum:04x}\n"
    
    # 如果是Echo Request/Reply，显示ID和序列号
    if hasattr(icmp_packet, 'id'):
        packet_info["detail"] += f"标识符: {icmp_packet.id}\n"
    if hasattr(icmp_packet, 'seq'):
        packet_info["detail"] += f"序列号: {icmp_packet.seq}\n"
    if hasattr(icmp_packet, 'gw'):
        packet_info["detail"] += f"网关: {icmp_packet.gw}\n"
    if hasattr(icmp_packet, 'ptr'):
        packet_info["detail"] += f"指针: {icmp_packet.ptr}\n"
    packet_info["detail"] += "\n"
    
    # 尝试提取应用层数据
    if packet.haslayer(scapy.Raw):
        packet_info["data"] = packet[scapy.Raw].load

def process_icmpv6(packet: scapy.Packet, packet_info: Dict[str, Any]):
    """处理ICMPv6层"""
    if ICMPv6 not in packet:
        return

    icmpv6_packet = packet[ICMPv6]
    packet_info["protocol"] = "ICMPv6"
    packet_info["src_port"] = "ICMPv6"
    packet_info["dst_port"] = "ICMPv6"
    
    # 获取ICMPv6类型和代码
    icmp_type = icmpv6_packet.type
    icmpv6_types = {
        1: "Destination Unreachable",
        2: "Packet Too Big",
        3: "Time Exceeded",
        4: "Parameter Problem",
        128: "Echo Request",
        129: "Echo Reply",
        133: "Router Solicitation",
        134: "Router Advertisement",
        135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
        137: "Redirect Message",
        142: "Inverse Neighbor Discovery Solicitation Message",
        143: "Inverse Neighbor Discovery Advertisement Message"
    }
    icmpv6_type_name = icmpv6_types.get(icmp_type, f"Unknown Type {icmp_type}")
    icmp_code = icmpv6_packet.code
    
    packet_info["info"] = f"ICMPv6 {icmpv6_type_name} (Type={icmp_type}, Code={icmp_code})"
    
    # 详细信息
    packet_info["detail"] += f"=== ICMPv6 层 ===\n"
    packet_info["detail"] += f"类型: {icmp_type} ({icmpv6_type_name})\n"
    packet_info["detail"] += f"类型代码: {icmp_code}\n"
    packet_info["detail"] += f"校验和: 0x{icmpv6_packet.chksum:04x}\n"
    
    if hasattr(icmpv6_packet, 'id'):
        packet_info["detail"] += f"标识符: {icmpv6_packet.id}\n"
    if hasattr(icmpv6_packet, 'seq'):
        packet_info["detail"] += f"序列号: {icmpv6_packet.seq}\n"
    if hasattr(icmpv6_packet, 'mtu'):
        packet_info["detail"] += f"MTU: {icmpv6_packet.mtu}\n"
    packet_info["detail"] += "\n"
    
    # 尝试提取应用层数据
    if packet.haslayer(scapy.Raw):
        packet_info["data"] = packet[scapy.Raw].load

def process_tcp(packet: scapy.Packet, packet_info: Dict[str, Any]):
    """处理TCP层"""
    if TCP not in packet:
        return
    
    tcp_packet = packet[TCP]
    packet_info["protocol"] = "TCP"
    sport = tcp_packet.sport
    dport = tcp_packet.dport
    packet_info["src_port"] = str(sport)
    packet_info["dst_port"] = str(dport)

    def _get_tcp_flags(flags):
        """解析TCP标志位"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return ",".join(flag_names)
    
    flags = _get_tcp_flags(tcp_packet.flags)
    
    # 获取端口名称
    sport_name = get_port_name(sport, "TCP")
    dport_name = get_port_name(dport, "TCP")
    
    # 构建信息摘要，包含端口名称
    if sport_name and dport_name:
        packet_info["info"] = f"TCP {sport_name}({sport}) -> {dport_name}({dport}) {flags}"
    elif sport_name:
        packet_info["info"] = f"TCP {sport_name}({sport}) -> {dport} {flags}"
    elif dport_name:
        packet_info["info"] = f"TCP {sport} -> {dport_name}({dport}) {flags}"
    else:
        packet_info["info"] = f"TCP {sport} -> {dport} {flags}"
    
    # 详细信息
    packet_info["detail"] += f"=== TCP 层 ===\n"
    packet_info["detail"] += f"源端口: {sport} {sport_name if sport_name else ''}\n"
    packet_info["detail"] += f"目的端口: {dport} {dport_name if dport_name else ''}\n"
    packet_info["detail"] += f"序列号seq: {tcp_packet.seq}\n"
    packet_info["detail"] += f"确认号ack: {tcp_packet.ack}\n"
    packet_info["detail"] += f"头部长度: {tcp_packet.dataofs * 4} 字节\n"
    
    # 详细的标志位信息
    packet_info["detail"] += f"标志: {flags}\n"
    if tcp_packet.flags & 0x01: packet_info["detail"] += f"  - FIN: 连接终止\n"
    if tcp_packet.flags & 0x02: packet_info["detail"] += f"  - SYN: 同步序号\n"
    if tcp_packet.flags & 0x04: packet_info["detail"] += f"  - RST: 重置连接\n"
    if tcp_packet.flags & 0x08: packet_info["detail"] += f"  - PSH: 推送数据\n"
    if tcp_packet.flags & 0x10: packet_info["detail"] += f"  - ACK: 确认\n"
    if tcp_packet.flags & 0x20: packet_info["detail"] += f"  - URG: 紧急指针\n"
    
    # 其他TCP字段
    packet_info["detail"] += f"窗口大小: {tcp_packet.window}\n"
    packet_info["detail"] += f"校验和: 0x{tcp_packet.chksum:04x}\n"
    packet_info["detail"] += f"紧急指针: {tcp_packet.urgptr}\n"
    packet_info["detail"] += f"数据包总长度: {len(tcp_packet)} 字节\n"
    
    # 可选字段（如果存在）
    if tcp_packet.options:
        packet_info["detail"] += f"选项: {tcp_packet.options}\n"
    packet_info["detail"] += "\n"
                
    # 尝试提取应用层数据
    if packet.haslayer(scapy.Raw):
        packet_info["data"] = packet[scapy.Raw].load

def process_udp(packet: scapy.Packet, packet_info: Dict[str, Any]):
    """处理UDP层"""
    if UDP not in packet:
        return
    udp_packet = packet[UDP]
    packet_info["protocol"] = "UDP"
    sport = udp_packet.sport
    dport = udp_packet.dport
    packet_info["src_port"] = str(sport)
    packet_info["dst_port"] = str(dport)
    
    # 获取端口名称
    sport_name = get_port_name(sport, "UDP")
    dport_name = get_port_name(dport, "UDP")
    
    # 构建信息摘要，包含端口名称
    if sport_name and dport_name:
        packet_info["info"] = f"UDP {sport_name}({sport}) -> {dport_name}({dport})"
    elif sport_name:
        packet_info["info"] = f"UDP {sport_name}({sport}) -> {dport}"
    elif dport_name:
        packet_info["info"] = f"UDP {sport} -> {dport_name}({dport})"
    else:
        packet_info["info"] = f"UDP {sport} -> {dport}"
    
    # 详细信息
    packet_info["detail"] += f"=== UDP 层 ===\n"
    packet_info["detail"] += f"源端口: {sport} {sport_name if sport_name else ''}\n"
    packet_info["detail"] += f"目的端口: {dport} {dport_name if dport_name else ''}\n"
    packet_info["detail"] += f"数据包总长度: {udp_packet.len} 字节\n"
    packet_info["detail"] += f"校验和: 0x{udp_packet.chksum:04x}\n"
    
    # 数据长度计算
    header_len = 8  # UDP头部固定8字节
    data_len = udp_packet.len - header_len
    packet_info["detail"] += f"数据长度: {data_len} 字节\n\n"
    
    # 尝试提取应用层数据
    if packet.haslayer(scapy.Raw):
        packet_info["data"] = packet[scapy.Raw].load


def reassemble_packet(Sniffer):
    """重组分片数据包"""
    if Sniffer.selected_packet_index < 0:
        return
        
    # 获取选中的数据包
    selected_packet = Sniffer.packet_list[Sniffer.selected_packet_index]
    if IP not in selected_packet["raw"]:
        messagebox.showinfo("提示", "选中的数据包不是IP数据包，无法重组")
        return
        
    # 获取当前选中的IP数据包信息
    selected_ip = selected_packet["raw"][IP]
    ip_id = selected_ip.id  # 获取IP标识，相同标识的分片属于同一个原始数据包
    src_ip = selected_ip.src
    dst_ip = selected_ip.dst
    proto = selected_ip.proto
    
    # 收集具有相同IP ID、源IP、目的IP和协议的所有分片及其对应的packet_info
    fragments_with_info = []
    max_offset = 0
    for packet_info in Sniffer.packet_list:
        if IP in packet_info["raw"]:
            ip_packet = packet_info["raw"][IP]
            # 检查是否为相关分片
            if (ip_packet.id == ip_id and 
                ip_packet.src == src_ip and 
                ip_packet.dst == dst_ip and 
                ip_packet.proto == proto):
                # 计算分片的数据长度（总长度 - IP头部长度）
                ip_header_length = ip_packet.ihl * 4  # ihl是4字节的单位
                fragment_data_length = ip_packet.len - ip_header_length
                
                # 收集分片信息，包括偏移量、数据、长度和原始packet_info
                fragments_with_info.append((ip_packet.frag, ip_packet, fragment_data_length, packet_info))
                
                # 计算最大偏移量，用于确定总数据大小
                current_max_offset = ip_packet.frag * 8 + fragment_data_length
                if current_max_offset > max_offset:
                    max_offset = current_max_offset
    
    if not fragments_with_info:
        messagebox.showinfo("提示", "未找到相关的分片数据包")
        return
        
    # 按分片偏移量排序
    fragments_with_info.sort(key=lambda x: x[0])
    
    # 尝试重组数据包
    try:
        # 直接拼接分组内所有数据包的数据部分
        reassembled_data = b""

        for _, fragment, _, packet_info in fragments_with_info:
            # 优先使用packet_info中已解析的数据
            if packet_info["data"]:
                fragment_data = packet_info["data"]
            else:
                # 如果没有预解析数据，直接从IP包中提取载荷
                ip_header_length = fragment.ihl * 4
                fragment_data = bytes(fragment)[ip_header_length:]
            # 将当前分片数据添加到重组数据中
            reassembled_data += fragment_data
            
        # 检查分片完整性
        is_complete = True
        missing_fragments = []
        
        # 检查从偏移量0开始的连续性
        if not any(offset == 0 for offset, _, _, _ in fragments_with_info):
            is_complete = False
            missing_fragments.append("第一个分片(偏移量0)")
        # 检查中间分片的连续性
        for i in range(len(fragments_with_info) - 1):
            current_offset, _, current_length, _ = fragments_with_info[i]
            next_offset, _, _, _ = fragments_with_info[i + 1]
            # 检查当前分片结束位置是否与下一个分片开始位置连续
            if (current_offset * 8 + current_length) != (next_offset * 8):
                is_complete = False
                missing_fragments.append(f"偏移量 {current_offset * 8 + current_length} 到 {next_offset * 8}")
        # 检查是否有最后一个分片（没有MF标志）
        if not any(not (fragment.flags & 0x2) for _, fragment, _, _ in fragments_with_info):
            is_complete = False
            missing_fragments.append("最后一个分片(没有MF标志)")
        
        reassembled_detail = "=== 重组结果 ===\n"
        reassembled_detail += f"IP ID（数据报标识）: {ip_id}\n"
        reassembled_detail += f"源IP: {src_ip}\n"
        reassembled_detail += f"目的IP: {dst_ip}\n"
        reassembled_detail += f"协议: {proto}\n"
        reassembled_detail += f"数据长度: {max_offset} 字节\n"
        reassembled_detail += f"是否完整: {'是' if is_complete else '否'}\n"
        reassembled_detail += f"缺失分片: {', '.join(missing_fragments) if not is_complete else '无'}\n\n"
        # 只保留 TCP/UDP 层及之后的信息，去掉 IP 层及之前的内容
        original_detail = fragments_with_info[0][3]["detail"]
        lines = original_detail.splitlines()
        start_idx = 0
        for idx, line in enumerate(lines):
            if line.startswith("=== TCP 层 ===") or line.startswith("=== UDP 层 ==="):
                start_idx = idx
                break
        reassembled_detail += "\n".join(lines[start_idx:-2])

        return reassembled_detail, reassembled_data 
    except Exception as e:
        messagebox.showerror("重组错误", f"重组过程中发生错误: {str(e)}")
        return None, None
