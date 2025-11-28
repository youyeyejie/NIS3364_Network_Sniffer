import binascii
import argparse

def hex_to_png(hex_data, output_file):
    """
    将十六进制数据转换为PNG文件
    
    Args:
        hex_data (str): 包含空格和换行的十六进制字符串
        output_file (str): 输出的PNG文件路径
    """
    try:
        # 移除所有空格和换行符
        clean_hex = hex_data.replace(" ", "").replace("\n", "").replace("\r", "")
        
        # 检查十六进制字符串长度是否为偶数
        if len(clean_hex) % 2 != 0:
            raise ValueError("十六进制数据长度必须为偶数")
        
        # 将十六进制转换为二进制数据
        binary_data = binascii.unhexlify(clean_hex)
        
        # 验证是否为PNG文件（检查文件头）
        if not binary_data.startswith(b'\x89PNG\r\n\x1a\n'):
            print("警告：数据似乎不是有效的PNG格式")
        
        # 写入文件
        with open(output_file, 'wb') as f:
            f.write(binary_data)
        
        print(f"成功生成PNG文件：{output_file}")
        
    except binascii.Error as e:
        print(f"十六进制解码错误：{e}")
    except ValueError as e:
        print(f"数据格式错误：{e}")
    except Exception as e:
        print(f"发生错误：{e}")

def main():
    # 设置命令行参数
    parser = argparse.ArgumentParser(description='将包含空格和换行的十六进制数据转换为PNG图片')
    parser.add_argument('-i', '--input', help='输入的十六进制文件路径', required=True)
    parser.add_argument('-o', '--output', help='输出的PNG文件路径', default='output.png')
    
    args = parser.parse_args()
    
    hex_data = ""
    
    # 从文件读取或直接获取数据
    if not args.input:
        return

    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            hex_data = f.read()
    except FileNotFoundError:
        print(f"错误：找不到文件 {args.input}")
        return
    
    if not hex_data:
        print("错误：没有提供十六进制数据")
        return
    
    # 转换并保存PNG
    hex_to_png(hex_data, args.output)

if __name__ == "__main__":
    main()