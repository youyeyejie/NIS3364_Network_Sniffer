import os
import tkinter as tk
from sniffer import NetworkSniffer

def main():
    """主函数"""
    # 检查是否以管理员/root权限运行
    if os.name == "nt":  # Windows
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            pass
    else:  # Unix/Linux
        is_admin = (os.geteuid() == 0)

    root = tk.Tk()
    app = NetworkSniffer(root, is_admin)
    
    # 设置程序退出处理
    def on_closing():
        if app.is_sniffing:
            app._pause_sniffing()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()