import threading
import tkinter as tk
import psutil
from tkinter import ttk, filedialog, scrolledtext, messagebox
from datetime import datetime
from typing import Dict, List, Any
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, _ICMPv6 as ICMPv6
from scapy.utils import wrpcap, rdpcap

from process_packet import *

class NetworkSniffer:
    """网络嗅探器主类"""
    
    def __init__(self, root: tk.Tk, is_admin):
        """初始化嗅探器"""
        self.root = root
        if is_admin:
            self.root.title("网络嗅探器（管理员模式）")
        else:
            self.root.title("网络嗅探器（建议打开管理员模式以体验完整功能）")
        self.root.geometry("1200x800")
        self.root.minsize(1200, 800)
        self.fonts = ("SimHei", 10)
        
        # 程序状态变量
        self.is_sniffing = False
        self.sniff_thread = None
        self.packet_list: List[Dict[str, Any]] = []  # 当前显示的数据包列表
        self.original_packet_list: List[Dict[str, Any]] = []  # 存储原始数据包列表
        self.selected_packet_index = -1
        self.protocol_filters = {}
        self.current_interface = None
        self.packets_to_save = []
        self.is_loading_from_pcap = False  # 标志是否从PCAP文件加载数据
        self.is_filtered = False  # 标志当前是否处于筛选状态
        self.is_promiscuous = False  # 标志是否启用混杂模式，默认关闭
        self.is_admin = is_admin
        
        # 初始化界面
        self._create_widgets()
        self._layout_widgets()
        self._setup_events()
        
        # 加载网络接口
        self.load_network_interfaces()
    
    def _create_widgets(self):
        """创建界面组件"""
        # 顶部功能区域
        self.top_frame = ttk.Frame(self.root, padding="5")
        
        # 网卡选择
        ttk.Label(self.top_frame, text="选择网卡:").pack(side=tk.LEFT, padx=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(self.top_frame, textvariable=self.interface_var, width=30)
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        # 协议选择
        ttk.Label(self.top_frame, text="协议过滤:").pack(side=tk.LEFT, padx=5)
        self.protocol_var = tk.StringVar(value="全部")
        protocols = ["全部", "TCP", "UDP","IPv4", "IPv6", "ICMP", "ICMPv6", "ARP"]
        self.protocol_combo = ttk.Combobox(self.top_frame, textvariable=self.protocol_var, values=protocols, width=10)
        self.protocol_combo.pack(side=tk.LEFT, padx=5)
        
        # 控制按钮 - 合并开始/暂停为一个状态切换按钮
        self.control_button = ttk.Button(self.top_frame, text="开始嗅探", command=self.toggle_sniffing)
        self.control_button.pack(side=tk.LEFT, padx=5)
        self.promisc_button = ttk.Button(self.top_frame, text="开启混杂", command=self.toggle_promiscuous_mode, state=tk.DISABLED if not self.is_admin else tk.NORMAL)  
        self.promisc_button.pack(side=tk.LEFT, padx=5)
        self.clear_button = ttk.Button(self.top_frame, text="清空记录", command=self.clear_packets)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # 高级功能按钮
        self.filter_button = ttk.Button(self.top_frame, text="筛选记录", command=self.open_filter_dialog)
        self.filter_button.pack(side=tk.LEFT, padx=5)
        self.reassemble_button = ttk.Button(self.top_frame, text="数据重组", command=self.show_reassembled_packet, state=tk.DISABLED)
        self.reassemble_button.pack(side=tk.LEFT, padx=5)
        self.save_button = ttk.Button(self.top_frame, text="保存PCAP", command=self.save_to_pcap)
        self.save_button.pack(side=tk.LEFT, padx=5)
        self.load_button = ttk.Button(self.top_frame, text="加载PCAP", command=self.load_from_pcap)
        self.load_button.pack(side=tk.LEFT, padx=5)
        
        # 主体区域 - 数据包列表
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.packet_tree = ttk.Treeview(self.main_frame, columns=("index", "time", "src", "src_port", "dst", "dst_port", "protocol", "length", "is_fragment", "info"), show="headings")
        
        # 设置列标题
        self.packet_tree.heading("index", text="序号")
        self.packet_tree.heading("time", text="时间戳")
        self.packet_tree.heading("src", text="源地址")
        self.packet_tree.heading("src_port", text="源端口")
        self.packet_tree.heading("dst", text="目的地址")
        self.packet_tree.heading("dst_port", text="目的端口")
        self.packet_tree.heading("protocol", text="协议")
        self.packet_tree.heading("length", text="长度")
        self.packet_tree.heading("is_fragment", text="分片")
        self.packet_tree.heading("info", text="信息")
        
        # 设置列宽
        self.packet_tree.column("index", width=40)
        self.packet_tree.column("time", width=180)
        self.packet_tree.column("src", width=180)
        self.packet_tree.column("src_port", width=60)
        self.packet_tree.column("dst", width=180)
        self.packet_tree.column("dst_port", width=60)
        self.packet_tree.column("protocol", width=60)
        self.packet_tree.column("length", width=60)
        self.packet_tree.column("is_fragment", width=40)
        self.packet_tree.column("info", width=300)
        
        # 添加滚动条
        self.tree_scrollbar = ttk.Scrollbar(self.main_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscroll=self.tree_scrollbar.set)
        
        # 底部详细信息区域
        self.bottom_frame = ttk.Frame(self.root)
        
        # 左侧 - 数据包详细信息
        self.detail_frame = ttk.LabelFrame(self.bottom_frame, text="详细信息", padding="5")
        self.detail_text = scrolledtext.ScrolledText(self.detail_frame, wrap=tk.WORD, spacing1=4, spacing2=4)
        self.detail_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # 右侧 - 数据字段
        self.data_frame = ttk.LabelFrame(self.bottom_frame, text="数据字段", padding="5")
        # 编解码选择
        self.encode_frame = ttk.Frame(self.data_frame)
        self.encode_var = tk.StringVar(value="HEX")
        ttk.Radiobutton(self.encode_frame, text="HEX", variable=self.encode_var, value="HEX", command=self._update_data_view).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(self.encode_frame, text="ASCII", variable=self.encode_var, value="ASCII", command=self._update_data_view).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(self.encode_frame, text="UTF-8", variable=self.encode_var, value="UTF-8", command=self._update_data_view).pack(side=tk.LEFT, padx=5)
        self.encode_frame.pack(side=tk.TOP, fill=tk.X)
        
        # 数据显示区域
        self.data_text = scrolledtext.ScrolledText(self.data_frame, wrap=tk.WORD, spacing1=4, spacing2=4)
        self.data_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    def _layout_widgets(self):
        """布局界面组件"""
        # 顶部功能区域
        self.top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        # 主体数据包列表区域
        self.main_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 底部详细信息区域
        self.bottom_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 左右分栏
        self.detail_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.data_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
    
    def _setup_events(self):
        """设置事件处理"""
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_selected)
    
    def load_network_interfaces(self):
        """加载网络接口列表"""            
        try:
            interfaces = []
            for iface in psutil.net_if_addrs():
                interfaces.append(iface)
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_combo.current(0)  # 默认选择第一个接口（以太网）

        except Exception as e:
            messagebox.showerror("错误", f"加载网络接口失败: {str(e)}")

    def toggle_sniffing(self):
        """切换嗅探状态（开始/暂停）"""
        if not self.is_sniffing:
            self._start_sniffing()
        else:
            self._pause_sniffing()
    
    def toggle_promiscuous_mode(self):
        """切换混杂模式状态"""
        self.is_promiscuous = not self.is_promiscuous
        if self.is_promiscuous:
            self.promisc_button.config(text="关闭混杂")
            if self.is_sniffing:
                messagebox.showinfo("提示", "已启用混杂模式。需要重新开始嗅探以应用更改。")
        else:
            self.promisc_button.config(text="开启混杂")
            if self.is_sniffing:
                messagebox.showinfo("提示", "已关闭混杂模式。需要重新开始嗅探以应用更改。")
    
    def _start_sniffing(self):
        """开始嗅探数据包"""
        if self.is_sniffing:
            return
            
        # 获取选中的接口和协议
        interface = self.interface_var.get()
        if not interface:
            messagebox.showwarning("警告", "请选择一个网络接口")
            return
        protocol_filter = self.protocol_var.get()
        
        # 设置嗅探标志
        self.is_sniffing = True

        # 禁用接口和协议选择
        self.interface_combo.config(state=tk.DISABLED)
        self.protocol_combo.config(state=tk.DISABLED)
        # 禁用保存、筛选、保存和加载按钮，更新控制按钮
        self.control_button.config(text="暂停嗅探")
        self.save_button.config(state=tk.DISABLED)
        self.load_button.config(state=tk.DISABLED)
        self.filter_button.config(state=tk.DISABLED)
        # 禁用混杂模式切换按钮
        self.promisc_button.config(state=tk.DISABLED)
        
        # 开始嗅探线程
        self.sniff_thread = threading.Thread(target=self._sniff_packets, args=(interface, protocol_filter), daemon=True)
        self.sniff_thread.start()
    
    def _pause_sniffing(self):
        """暂停嗅探"""
        self.is_sniffing = False
        if self.sniff_thread:
            self.sniff_thread.join(timeout=0)
        
        self.control_button.config(text="开始嗅探")
        self.interface_combo.config(state=tk.NORMAL)
        self.protocol_combo.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        self.load_button.config(state=tk.NORMAL)
        self.filter_button.config(state=tk.NORMAL)
        # 启用混杂模式切换按钮
        self.promisc_button.config(state=tk.NORMAL if self.is_admin else tk.DISABLED)
    
    def _sniff_packets(self, interface: str, protocol_filter: str):
        """数据包嗅探函数，支持捕获非本机数据包（需要管理员权限和混杂模式）"""
        def packet_callback(packet):
            if not self.is_sniffing:
                return False
                
            self._process_packet(packet)
        
        # 构建过滤器表达式
        filter_expr = ""
        if protocol_filter != "全部":
            if protocol_filter == "IPv4":
                filter_expr = "ip"
            elif protocol_filter == "IPv6":
                filter_expr = "ip6"
            else:
                filter_expr = protocol_filter.lower()
        
        try:
            # 根据is_promiscuous标志决定是否启用混杂模式
            scapy.sniff(iface=interface, prn=packet_callback, store=False, 
                        stop_filter=lambda _: not self.is_sniffing, 
                        filter=filter_expr, 
                        promisc=self.is_promiscuous)  # 根据标志启用/禁用混杂模式
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("错误", f"嗅探失败: {str(e)}"))
            self.root.after(0, self._pause_sniffing)
    
    def _process_packet(self, packet):
        """处理捕获到的数据包"""
        # 生成数据包信息
        packet_info = {
            "raw": packet,
            "time": "",
            "src": "",
            "src_port": "",
            "dst": "",
            "dst_port": "",
            "protocol": "Unknown",
            "length": "",
            "is_fragment": "",
            "info": "",
            "detail": "",
            "data": b""
        }
        
        # 使用整个数据包长度
        packet_info["length"] = str(len(packet)) + " B"
        
        # 将原始数据包添加到保存列表中（仅在实时嗅探时，加载PCAP时已经设置）
        if not hasattr(self, 'is_loading_from_pcap') or not self.is_loading_from_pcap:
            self.packets_to_save.append(packet)
        
        # 根据来源使用不同的时间戳
        if hasattr(self, 'is_loading_from_pcap') and self.is_loading_from_pcap and hasattr(packet, 'time'):
            # 从PCAP文件加载时，使用数据包自带的时间戳
            packet_time_float = float(packet.time)
            packet_timestamp = datetime.fromtimestamp(packet_time_float)
            timestamp = packet_timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-1]  # 保留5位小数
        else:
            # 实时捕获时，使用当前时间
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-1]
        
        packet_info["time"] = timestamp

        print(f'[*] {timestamp} - {packet.summary()}')  # 控制台输出简要信息
        
        # 解析以太网层
        if Ether in packet:
            process_ether(packet, packet_info)       
        # 解析ARP层
        if ARP in packet:
            process_arp(packet, packet_info)
        # 解析IP层
        if IP in packet:
            process_ip(packet, packet_info)
            # 解析ICMP层
            if ICMP in packet:
                process_icmp(packet, packet_info)
        # 解析IPv6层
        if IPv6 in packet:
            process_ipv6(packet, packet_info)
            # 解析ICMPv6层
            if packet[IPv6].nh == 58:
                process_icmpv6(packet, packet_info)
        # 解析TCP层
        if TCP in packet:
            process_tcp(packet, packet_info)
        # 解析UDP层
        if UDP in packet:
            process_udp(packet, packet_info)         
        
        # 添加到原始数据包列表
        self.original_packet_list.append(packet_info.copy())
        packet_number = len(self.packet_list) + 1
        
        # 添加到显示列表
        self.packet_list.append(packet_info)
        
        # 实时嗅探时逐个更新UI，PCAP加载时由批量更新处理
        if not hasattr(self, 'is_loading_from_pcap') or not self.is_loading_from_pcap:
            # 在GUI中更新，传递正确的序号
            self.root.after(0, lambda p=packet_info, n=packet_number: self._update_packet_list(p, n))
        
        # 返回处理后的数据包信息，供PCAP加载时的批量更新使用
        return packet_info
     
    def _apply_filters(self, packet_info):
        """根据设置的过滤器筛选数据包"""
        # 检查每个过滤器条件
        for filter_key, filter_value in self.protocol_filters.items():
            # 如果过滤器值为空，则跳过该过滤器
            if not filter_value:
                continue
            
            # 源IP过滤
            if filter_key == "src_ip":
                if filter_value not in packet_info.get("src", ""):
                    return False
            # 源mac过滤
            elif filter_key == "src_mac":
                if filter_value not in packet_info.get("src", ""):
                    return False
            # 源端口过滤
            elif filter_key == "src_port":
                if filter_value not in packet_info.get("src_port", ""):
                    return False
            
            # 目的IP过滤
            elif filter_key == "dst_ip":
                if filter_value not in packet_info.get("dst", ""):
                    return False
            # 目的mac过滤
            elif filter_key == "dst_mac":
                if filter_value not in packet_info.get("dst", ""):
                    return False
            # 目的端口过滤
            elif filter_key == "dst_port":
                if filter_value not in packet_info.get("dst_port", ""):
                    return False
        # 所有过滤器都匹配（或没有设置过滤器）
        return True
    
    def _apply_filters_to_captured_packets(self):
        """对已捕获的数据包应用筛选条件"""
        # 使用原始数据包列表进行筛选
        filtered_packets = []
        
        # 如果有原始数据包，则进行筛选
        if self.original_packet_list:
            for packet in self.original_packet_list:
                if self._apply_filters(packet):
                    filtered_packets.append(packet)
            
            # 更新显示的数据包列表
            self.packet_list = filtered_packets
            self.is_filtered = True
            
            # 清空当前的树状视图
            self.packet_tree.delete(*self.packet_tree.get_children())
            
            # 重新插入筛选后的数据包
            for i, packet in enumerate(self.packet_list, 1):
                self.packet_tree.insert("", tk.END, values=(
                    i,
                    packet["time"],
                    packet["src"],
                    packet["src_port"],
                    packet["dst"],
                    packet["dst_port"],
                    packet["protocol"],
                    packet["length"],
                    packet["is_fragment"],
                    packet["info"]
                ))
            
            # 重置选中状态
            self.selected_packet_index = -1
            self.detail_text.delete(1.0, tk.END)
            self.data_text.delete(1.0, tk.END)
            self.reassemble_button.config(state=tk.DISABLED)
    
    def open_filter_dialog(self):
        """打开筛选对话框"""
        # 创建筛选对话框
        filter_window = tk.Toplevel(self.root)
        filter_window.title("高级筛选")
        filter_window.geometry("600x300")
        filter_window.transient(self.root)
        filter_window.grab_set()
        
        # 创建一个容器框架来居中内容
        content_frame = ttk.Frame(filter_window)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # IP地址筛选 - 调整为居中布局
        # 源IP（左）
        ttk.Label(content_frame, text="源IP:").grid(row=0, column=0, sticky=tk.E, padx=(10, 10), pady=10)
        src_ip_var = tk.StringVar(value=self.protocol_filters.get("src_ip", ""))
        ttk.Entry(content_frame, textvariable=src_ip_var, width=25).grid(row=0, column=1, pady=10)
        # 目的IP（右）
        ttk.Label(content_frame, text="目的IP:").grid(row=0, column=2, sticky=tk.E, padx=(10, 10), pady=10)
        dst_ip_var = tk.StringVar(value=self.protocol_filters.get("dst_ip", ""))
        ttk.Entry(content_frame, textvariable=dst_ip_var, width=25).grid(row=0, column=3, pady=10)
        
        # 源mac（左）
        ttk.Label(content_frame, text="源MAC:").grid(row=1, column=0, sticky=tk.E, padx=(10, 10), pady=10)
        src_mac_var = tk.StringVar(value=self.protocol_filters.get("src_mac", ""))
        ttk.Entry(content_frame, textvariable=src_mac_var, width=25).grid(row=1, column=1, pady=10)
        # 目的mac（右）
        ttk.Label(content_frame, text="目的MAC:").grid(row=1, column=2, sticky=tk.E, padx=(10, 10), pady=10)
        dst_mac_var = tk.StringVar(value=self.protocol_filters.get("dst_mac", ""))
        ttk.Entry(content_frame, textvariable=dst_mac_var, width=25).grid(row=1, column=3, pady=10)

        # 源端口（左）
        ttk.Label(content_frame, text="源端口:").grid(row=2, column=0, sticky=tk.E, padx=(10, 10), pady=10)
        src_port_var = tk.StringVar(value=self.protocol_filters.get("src_port", ""))
        ttk.Entry(content_frame, textvariable=src_port_var, width=25).grid(row=2, column=1, pady=10)
        # 目的端口（右）
        ttk.Label(content_frame, text="目的端口:").grid(row=2, column=2, sticky=tk.E, padx=(10, 10), pady=10)
        dst_port_var = tk.StringVar(value=self.protocol_filters.get("dst_port", ""))
        ttk.Entry(content_frame, textvariable=dst_port_var, width=25).grid(row=2, column=3, pady=10)
        
        # 创建按钮容器框架
        button_frame = ttk.Frame(content_frame)
        button_frame.grid(row=4, column=0, columnspan=4, pady=20, sticky="nsew")
        
        # 应用按钮
        def apply_filter():
            # 保存筛选条件
            self.protocol_filters = {
                "src_ip": src_ip_var.get(),
                "dst_ip": dst_ip_var.get(),
                "src_mac": src_mac_var.get(),
                "dst_mac": dst_mac_var.get(),
                "src_port": src_port_var.get(),
                "dst_port": dst_port_var.get(),
            }
            
            # 应用筛选到已捕获的数据包
            self._apply_filters_to_captured_packets()
            filter_window.destroy()
        
        # 重置按钮
        def reset_filter():
            # 清空筛选条件
            src_ip_var.set("")
            dst_ip_var.set("")
            src_mac_var.set("")
            dst_mac_var.set("")
            src_port_var.set("")
            dst_port_var.set("")
        
        # 创建对称布局的按钮，确保居中显示
        button_width = 10
        button_container = ttk.Frame(button_frame)
        button_container.pack(anchor="center")
        ttk.Button(button_container, text="重置", command=reset_filter, width=button_width).pack(side=tk.LEFT, padx=20)
        ttk.Button(button_container, text="应用", command=apply_filter, width=button_width).pack(side=tk.LEFT, padx=20)
        
        # 使所有列权重相等以确保居中对称
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
        content_frame.grid_columnconfigure(2, weight=1)
        content_frame.grid_columnconfigure(3, weight=1)
        
        # 确保按钮框架在中间居中
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
   
    def _update_packet_list(self, packet_info, packet_number):
        """更新数据包列表视图"""
        self.packet_tree.insert("", tk.END, values=(
            packet_number,
            packet_info["time"],
            packet_info["src"],
            packet_info["src_port"],
            packet_info["dst"],
            packet_info["dst_port"],
            packet_info["protocol"],
            packet_info["length"],
            packet_info["is_fragment"],
            packet_info["info"]
        ))
        
        # 自动滚动到底部
        self.packet_tree.yview_moveto(1.0)
    
    def on_packet_selected(self, event):
        """当选中数据包时触发"""
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        # 获取选中的索引
        item = selection[0]
        values = self.packet_tree.item(item, "values")
        if values:
            # 序号是从1开始的，需要减1转换为0索引
            index = int(values[0]) - 1
            self.selected_packet_index = index
            
            # 更新详细信息和数据字段
            self._update_packet_details(index)
    
    def _update_packet_details(self, index):
        """更新选中数据包的详细信息"""
        if 0 <= index < len(self.packet_list):
            packet_info = self.packet_list[index]
            
            # 更新详细信息
            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(tk.END, packet_info["detail"])
            
            # 更新数据字段
            self._update_data_view()
            
            # 启用重组按钮（如果是分片数据包）
            if IP in packet_info["raw"]:
                ip_packet = packet_info["raw"][IP]
                # MF标志=0 表示开启分片功能
                # DF标志=1 表示后续还有分片
                # 当DF=0时，MF=1表示后续还有分片，offset>0表示分片偏移量大于0
                is_fragment = (not ip_packet.flags.DF) and (ip_packet.flags.MF or ip_packet.frag > 0)
                self.reassemble_button.config(state=tk.NORMAL if is_fragment else tk.DISABLED)
            else:
                self.reassemble_button.config(state=tk.DISABLED)
    
    def _update_data_view(self):
        """更新数据字段视图"""
        if self.selected_packet_index < 0 or self.selected_packet_index >= len(self.packet_list):
            return
            
        packet_info = self.packet_list[self.selected_packet_index]
        data = packet_info["data"]
        
        self.data_text.delete(1.0, tk.END)
        
        if not data:
            self.data_text.insert(tk.END, "[No data payload]")
            return
            
        encode_type = self.encode_var.get()
        
        try:
            if encode_type == "HEX":
                # 以十六进制格式显示
                hex_str = " ".join(f"{b:02x}" for b in data)
                # 每行显示16字节
                formatted_hex = ""
                for i in range(0, len(hex_str), 48):  # 16字节 * 3字符/字节 (XX )
                    formatted_hex += hex_str[i:i+48] + "\n"
                self.data_text.insert(tk.END, formatted_hex)
            elif encode_type == "ASCII":
                # 以ASCII格式显示
                ascii_str = "".join(chr(b) if 32 <= b <= 126 else '.' for b in data)
                self.data_text.insert(tk.END, ascii_str)
            elif encode_type == "UTF-8":
                # 尝试以UTF-8解码
                try:
                    utf8_str = data.decode('utf-8')
                    self.data_text.insert(tk.END, utf8_str)
                except UnicodeDecodeError:
                    self.data_text.insert(tk.END, "[Unable to decode as UTF-8]")
        except Exception as e:
            self.data_text.insert(tk.END, f"[Error displaying data: {str(e)}]")
    
    def clear_packets(self):
        """清空数据包列表"""
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.packet_list.clear()
        self.original_packet_list.clear()
        self.packets_to_save.clear()
        self.selected_packet_index = -1
        self.is_filtered = False
        self.detail_text.delete(1.0, tk.END)
        self.data_text.delete(1.0, tk.END)
        self.reassemble_button.config(state=tk.DISABLED)
    
    def show_reassembled_packet(self):
        reassembled_detail, reassembled_data = reassemble_packet(self)
        if reassembled_detail is None or reassembled_data is None:
            return

        # 显示重组结果
        result_window = tk.Toplevel(self.root)
        result_window.title("数据包重组结果")
        result_window.geometry("1200x600")  # 调整窗口大小以适应左右分栏
        result_window.transient(self.root)
        
        # 创建主容器，类似主界面的bottom_frame
        result_frame = ttk.Frame(result_window)
        result_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 设置result_frame的grid布局，调整左右分栏比例为1:2
        result_frame.grid_columnconfigure(0, weight=1)
        result_frame.grid_columnconfigure(1, weight=2)
        result_frame.grid_rowconfigure(0, weight=1)
        
        # 左侧 - 详细信息（类似主界面的detail_frame）
        detail_frame = ttk.LabelFrame(result_frame, text="详细信息", padding="5")
        detail_frame.grid(row=0, column=0, sticky="nsew", padx=5)
        detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, spacing1=4, spacing2=4)
        detail_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        # 右侧 - 数据字段（类似主界面的data_frame）
        data_frame = ttk.LabelFrame(result_frame, text="重组数据", padding="5")
        data_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        # 编解码选择（与主界面保持一致）
        encode_frame = ttk.Frame(data_frame)
        encode_var = tk.StringVar(value="HEX")
        ttk.Radiobutton(encode_frame, text="HEX", variable=encode_var, value="HEX").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(encode_frame, text="ASCII", variable=encode_var, value="ASCII").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(encode_frame, text="UTF-8", variable=encode_var, value="UTF-8").pack(side=tk.LEFT, padx=5)
        encode_frame.pack(side=tk.TOP, fill=tk.X)
        data_text = scrolledtext.ScrolledText(data_frame, wrap=tk.WORD, spacing1=4, spacing2=4)
        data_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # 详细信息内容
        detail_text.insert(tk.END, reassembled_detail)
        
        # 创建更新数据视图的函数
        def update_reassembled_data_view():
            data_text.delete(1.0, tk.END)
            encode_type = encode_var.get()
            
            try:
                if encode_type == "HEX":
                    # 以十六进制格式显示
                    hex_str = " ".join(f"{b:02x}" for b in reassembled_data)
                    formatted_hex = ""
                    for i in range(0, len(hex_str), 48):  # 每行16字节
                        formatted_hex += hex_str[i:i+48] + "\n"
                    data_text.insert(tk.END, formatted_hex)
                elif encode_type == "ASCII":
                    # 以ASCII格式显示
                    ascii_str = "".join(chr(b) if 32 <= b <= 126 else '.' for b in reassembled_data)
                    data_text.insert(tk.END, ascii_str)
                elif encode_type == "UTF-8":
                    # 尝试以UTF-8解码
                    try:
                        utf8_str = reassembled_data.decode('utf-8')
                        data_text.insert(tk.END, utf8_str)
                    except UnicodeDecodeError:
                        data_text.insert(tk.END, "[Unable to decode as UTF-8]")
            except Exception as e:
                data_text.insert(tk.END, f"[Error displaying data: {str(e)}]")
        
        # 绑定单选按钮事件
        encode_var.trace_add("write", lambda *args: update_reassembled_data_view())
        
        # 初始显示
        update_reassembled_data_view()
        
        # 添加按钮框架
        button_frame = ttk.Frame(result_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # 添加关闭按钮
        ttk.Button(button_frame, text="关闭", command=result_window.destroy).pack(side=tk.RIGHT, padx=10)

    def save_to_pcap(self):
        """保存为PCAP文件"""
        if not self.packets_to_save:
            messagebox.showinfo("提示", "没有捕获到数据包可保存")
            return
            
        # 只有在暂停嗅探时才能保存
        if self.is_sniffing:
            messagebox.showinfo("提示", "请先暂停嗅探后再保存PCAP文件")
            return
            
        try:
            # 打开文件对话框
            file_path = filedialog.asksaveasfilename(
                defaultextension=".pcap",
                filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*")]
            )
            
            if file_path:
                # 保存数据包
                wrpcap(file_path, self.packets_to_save)
                messagebox.showinfo("成功", f"数据包已保存到 {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {str(e)}")
    
    def load_from_pcap(self):
        """从PCAP文件加载数据包（使用线程避免GUI卡死）"""
        # 只有在暂停嗅探时才能导入
        if self.is_sniffing:
            messagebox.showinfo("提示", "请先暂停嗅探后再导入PCAP文件")
            return
            
        # 检查当前是否有内容，如果有则直接清空
        if self.packet_list:
            self.clear_packets()
        
        # 确保原始数据包列表为空
        self.original_packet_list.clear()
        # 重置筛选状态标志
        self.is_filtered = False
        # 设置加载标志
        self.is_loading_from_pcap = True
        
        try:
            # 打开文件对话框
            file_path = filedialog.askopenfilename(
                filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*")]
            )
            
            if file_path:
                # 加载结果变量
                load_result = {"success": False, "message": "", "count": 0}
                
                def _update_treeview_batch(packet_infos):
                    """批量更新Treeview中的数据包列表"""
                    # 收集所有要插入的数据包
                    for i, packet_info in enumerate(packet_infos):
                        packet_number = len(self.packet_list) - len(packet_infos) + i + 1
                        # 插入到Treeview中
                        self._update_packet_list(packet_info, packet_number)
                    # 滚动到底部
                    self.packet_tree.yview_moveto(1.0)
                
                def _load_packets_thread():
                    """在后台线程中加载数据包"""
                    try:
                        # 读取数据包并获取数量
                        packets = rdpcap(file_path)
                        total_count = len(packets)
                        
                        # 限制最大加载数量，避免内存问题
                        max_packets = 10000  # 设置上限
                        if total_count > max_packets:
                            self.root.after(0, lambda: messagebox.showwarning(
                                "提示", f"文件包含 {total_count} 个数据包，将只加载前 {max_packets} 个以保证性能"))
                            packets = packets[:max_packets]
                            total_count = max_packets
                        
                        # 重置packets_to_save列表并保存数据包引用
                        self.packets_to_save = list(packets)
                        
                        # 批量处理数据包
                        update_batch_size = 200  # 每批更新GUI的数据包数量
                        batch_packets = []
                        
                        for i, packet in enumerate(packets):
                            # 处理单个数据包
                            packet_info = self._process_packet(packet)
                            batch_packets.append(packet_info)
                            
                            # 每收集一定数量的数据包，批量更新GUI
                            if len(batch_packets) >= update_batch_size or i == total_count - 1:
                                # 复制当前批次，以便在后台线程继续处理时不被修改
                                current_batch = batch_packets.copy()
                                # 在主线程中更新GUI
                                self.root.after(0, lambda b=current_batch: _update_treeview_batch(b))
                                # 清空批次
                                batch_packets = []
                        
                        load_result["success"] = True
                        load_result["count"] = total_count
                    except Exception as e:
                        load_result["message"] = str(e)
                    finally:
                        # 显示结果
                        self.root.after(0, self._show_load_result, load_result)
                
                # 启动加载线程
                load_thread = threading.Thread(target=_load_packets_thread, daemon=True)
                load_thread.start()
                
        except Exception as e:
            messagebox.showerror("错误", f"加载失败: {str(e)}")
            # 重置加载标志
            self.is_loading_from_pcap = False
    
    def _show_load_result(self, load_result):
        """显示加载结果"""
        if load_result["success"]:
            messagebox.showinfo("成功", f"已加载 {load_result['count']} 个数据包")
        else:
            messagebox.showerror("错误", f"加载失败: {load_result['message']}")
        
        # 重置加载标志
        self.is_loading_from_pcap = False