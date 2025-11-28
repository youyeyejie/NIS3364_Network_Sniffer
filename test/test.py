
from scapy.all import IP, UDP, TCP, ICMP, ARP, Raw, fragment, send, conf
import psutil

def set_interface():
    # 获取所有网卡名称
    interfaces = psutil.net_if_addrs()
    iface_names = list(interfaces.keys())
    
    print("检测到以下网卡：")
    for idx, name in enumerate(iface_names, 1):
        print(f"{idx}. {name}")
    
    # # 让用户选择网卡
    # while True:
    #     try:
    #         choice = int(input("请选择要使用的网卡编号：")) - 1
    #         if 0 <= choice < len(iface_names):
    #             selected_iface = iface_names[choice]
    #             conf.iface = selected_iface
    #             print(f"已选择网卡：{selected_iface}")
    #             break
    #         else:
    #             print("编号无效，请重新输入！")
    #     except ValueError:
    #         print("请输入有效的数字编号！")
    
    conf.iface = iface_names[1] # 选择第二个网卡：以太网

def test_large_packet_fragmentation(dest_ip='192.168.1.1', sport=11451, dport=14514):
    """
    测试长报文分片发送
    发送超过MTU大小的数据包，将被分片传输
    """
    print("\n===== 开始测试长报文分片发送功能 =====")
    print(f"目标IP: {dest_ip}, 源端口: {sport}, 目标端口: {dport}")
    print("正在发送分片数据包...")
    
    # 使用TCP发送大数据包，设置DF=0允许分片
    readme_path = "../README.md"
    with open(readme_path, "rb") as f:
        readme_content = f.read()
    large_payload = readme_content.decode("utf-8")
    packet = IP(dst=dest_ip, id=11451) / TCP(dport=dport, sport=sport, flags="S")  / large_payload
    fragments = fragment(packet, fragsize=1000)
    send(fragments)
    print("分片数据包发送完成，请检查嗅探器是否正确重组数据包")
    print("==================================\n")

def test_image_transfer(dest_ip='192.168.1.1', sport=11451, dport=14514):
    """
    测试图片传输
    发送ICO格式的图片文件，测试嗅探器捕获能力
    """
    print("\n===== 开始测试图片传输功能 =====")
    print(f"目标IP: {dest_ip}, 源端口: {sport}, 目标端口: {dport}")
    print("正在发送图片数据...")
    
    # 读取ICO文件
    image_path = "../ico/Sniffer.png"
    with open(image_path, "rb") as img_file:
        image_data = img_file.read()
    packet = IP(dst=dest_ip, id=14514) / TCP(dport=dport, sport=sport, flags="S") / image_data
    fragments = fragment(packet, fragsize=1000)
    send(fragments)
    print("图片数据发送完成，请检查嗅探器是否正确捕获并重组ICO文件数据")
    print("==================================\n")

def test_various_protocols(dest_ip='192.168.1.1', sport=11451, dport=14514):
    """
    测试多种协议
    发送不同协议的数据包，测试嗅探器的协议识别能力
    """
    print("\n===== 开始测试多种协议功能 =====")
    print(f"目标IP: {dest_ip}, 源端口: {sport}, 目标端口: {dport}")
    print("正在发送不同协议的数据包...")
    
    # 1. ICMP协议测试（Ping）
    icmp_packet = IP(dst=dest_ip) / ICMP() / Raw(load=b'ICMP test data')
    send(icmp_packet, verbose=False)
    print("ICMP Ping请求发送完成，请检查嗅探器是否正确捕获")
    
    # 2. UDP协议测试
    udp_packet = IP(dst=dest_ip) / UDP(dport=dport, sport=sport) / Raw(load=b'UDP test data')
    send(udp_packet, verbose=False)
    print("UDP数据发送完成，请检查嗅探器是否正确捕获")
    
    # 3. TCP协议测试
    tcp_packet = IP(dst=dest_ip) / TCP(dport=dport, sport=sport, flags="S") / Raw(load=b'TCP test data')
    send(tcp_packet, verbose=False)
    print("TCP SYN包发送完成，请检查嗅探器是否正确捕获")

    # 4. ARP协议测试
    arp_packet = ARP(op=1, pdst=dest_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc="192.168.1.1", hwsrc="00:11:22:33:44:55")
    send(arp_packet, verbose=False)
    print("ARP请求发送完成，请检查嗅探器是否正确捕获")
    print("==================================\n")

if __name__ == "__main__":
    set_interface()
    test_large_packet_fragmentation()
    test_image_transfer()
    test_various_protocols()