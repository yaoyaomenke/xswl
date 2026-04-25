# 导入 Qiling 的 VFS 基类
from qiling import Qiling
from qiling.os.mapper import QlFsMappedObject
import uuid
import socket
import netifaces
import os
import re
import dns.resolver
# poll 事件常量
POLLIN = 0x001      # 有数据可读
POLLPRI = 0x002     # 有紧急数据可读
POLLOUT = 0x004     # 写操作不会阻塞
POLLERR = 0x008     # 发生错误
POLLHUP = 0x010     # 挂起
POLLNVAL = 0x020    # 无效的请求：fd 未打开
POLLRDNORM = 0x040  # 普通数据可读
POLLRDBAND = 0x080  # 带外数据可读
POLLWRNORM = 0x100  # 普通数据可写
POLLWRBAND = 0x200  # 带外数据可写
POLLMSG = 0x400     # SIGPOLL 消息可用
POLLREMOVE = 0x1000 # 移除 fd
# 在文件开头添加必要的导入
import select
import time
import struct

def handle_poll_syscall(ql: Qiling):
    """
    实现 poll 系统调用
    int poll(struct pollfd *fds, nfds_t nfds, int timeout)
    """
    fds_ptr = ql.arch.regs.rdi  # struct pollfd *
    nfds = ql.arch.regs.rsi  # nfds_t nfds
    timeout = ql.arch.regs.rdx  # int timeout

    # pollfd 结构体: fd(4) + events(2) + revents(2) = 8 字节
    POLLFD_SIZE = 8

    if nfds == 0:
        # 如果没有文件描述符，只是睡眠
        if timeout > 0:
            time.sleep(timeout / 1000.0)
        ql.arch.regs.rax = 0
        return 0

    # 用于 select 的文件描述符列表
    read_fds = []
    write_fds = []
    error_fds = []

    # 存储 pollfd 信息用于后续设置 revents
    pollfd_list = []

    for i in range(nfds):
        pollfd_addr = fds_ptr + i * POLLFD_SIZE
        fd_data = ql.mem.read(pollfd_addr, POLLFD_SIZE)
        fd, events, _ = struct.unpack('iHH', fd_data)  # 最后2字节是 revents（初始为0）

        pollfd_list.append({
            'addr': pollfd_addr,
            'fd': fd,
            'events': events,
            'revents': 0
        })

        if fd < 0:
            continue

        # 获取 Qiling 的文件描述符对象
        try:
            ql_fd = ql.os.fd[fd]

            # 根据 events 设置 select 监听
            if events & (POLLIN | 0x001):  # POLLIN 或普通读事件
                if hasattr(ql_fd, 'fileno') and ql_fd.fileno() != -1:
                    read_fds.append(ql_fd.fileno())
                elif hasattr(ql_fd, 'socket'):
                    # 对于 socket，直接使用其 fileno
                    read_fds.append(ql_fd.socket.fileno())

            if events & POLLOUT:
                if hasattr(ql_fd, 'fileno') and ql_fd.fileno() != -1:
                    write_fds.append(ql_fd.fileno())
                elif hasattr(ql_fd, 'socket'):
                    write_fds.append(ql_fd.socket.fileno())

            # 总是监听错误
            if hasattr(ql_fd, 'fileno') and ql_fd.fileno() != -1:
                error_fds.append(ql_fd.fileno())
            elif hasattr(ql_fd, 'socket'):
                error_fds.append(ql_fd.socket.fileno())

        except KeyError:
            # fd 无效
            for item in pollfd_list:
                if item['fd'] == fd:
                    item['revents'] = POLLNVAL

    # 执行 select
    try:
        if timeout < 0:
            # 无限等待
            timeout_param = None
        else:
            timeout_param = timeout / 1000.0

        if read_fds or write_fds or error_fds:
            rlist, wlist, xlist = select.select(read_fds, write_fds, error_fds, timeout_param)
        else:
            # 没有有效的 fd，只睡眠
            if timeout > 0:
                time.sleep(timeout / 1000.0)
            rlist, wlist, xlist = [], [], []

        # 设置 revents
        ready_count = 0
        for item in pollfd_list:
            if item['fd'] < 0:
                continue

            try:
                ql_fd = ql.os.fd[item['fd']]
                if hasattr(ql_fd, 'fileno') and ql_fd.fileno() != -1:
                    host_fd = ql_fd.fileno()
                elif hasattr(ql_fd, 'socket'):
                    host_fd = ql_fd.socket.fileno()
                else:
                    continue

                revents = 0
                if host_fd in rlist:
                    revents |= POLLIN
                if host_fd in wlist:
                    revents |= POLLOUT
                if host_fd in xlist:
                    revents |= POLLERR

                if revents != 0:
                    item['revents'] = revents
                    ready_count += 1

            except KeyError:
                item['revents'] = POLLNVAL
                ready_count += 1

        # 写回 revents
        for item in pollfd_list:
            if item['revents'] != 0 or item['fd'] < 0:
                # 读取原始数据，修改 revents 部分，写回
                fd_data = ql.mem.read(item['addr'], POLLFD_SIZE)
                fd, events = struct.unpack('iH', fd_data[:6])
                new_data = struct.pack('iHH', fd, events, item['revents'])
                ql.mem.write(item['addr'], new_data)

        ql.arch.regs.rax = ready_count
        return 0

    except Exception as e:
        print(f"[poll] 错误: {e}")
        ql.arch.regs.rax = -1
        return -1
# 1. 创建一个代表虚拟文件的类
class search_internet_infomation(QlFsMappedObject):
    # 定义文件的内容，可以在初始化时注入
    def __init__(self, file):
        self.content = file

    # 当程序调用 read 系统调用时，会调用此方法
    def read(self, size: int) -> bytes:
        if(self.content == "status"):
            mac_address = uuid.UUID(int=uuid.getnode()).hex[-12:].upper()
            mac_address = ':'.join([mac_address[i:i + 2] for i in range(0, 11, 2)])
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            output = os.popen("ipconfig /all").read()
            # print(output)
            ipv6 = re.findall(r"(([a-f0-9]{1,4}:){7}[a-f0-9]{1,4})", output, re.I)
            return (f"""[device]
managed=true
interface=e0
state=connected
carrier=true
mac={mac_address}
mtu=1500

[ipv4]
method=auto
dhcp-state=bound
address={local_ip}
netmask=255.255.255.0
gateway=192.168.1.1
dns=223.5.5.5

[ipv6]
link-local={ipv6[0][0]}
global={ipv6[0][0]}

[connectivity]
state=full
""").encode("ascii")
        if(self.content == "status"):return """
state=connected
connectivity=full
managed=true"""
        if(self.content =="ipv6"):
            output = os.popen("ipconfig /all").read()
            # print(output)
            ipv6 = re.findall(r"(([a-f0-9]{1,4}:){7}[a-f0-9]{1,4})", output, re.I)
            return f"""
link-local={ipv6[0][0]}
global={ipv6[0][0]}"""
        if(self.content =="ipv4"):
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            return f"""
method=auto
address={local_ip}
netmask=255.255.255.0
gateway={default_gateway}"""

    # 当程序调用 close 系统调用时，会调用此方法
    def close(self) -> int:
        # 可以在此执行清理工作
        return 0

def get_dns_servers():
    """获取系统配置的 DNS 服务器"""
    try:
        # 读取系统 DNS 配置
        resolver = dns.resolver.Resolver()
        dns_servers = resolver.nameservers

        if dns_servers:
            return dns_servers
        else:
            return ["未找到 DNS 服务器"]
    except Exception as e:
        return [f"错误: {e}"]
def get_ipv4_pone(domain):
    try:
        # socket.AF_INET 指定只获取 IPv4 地址
        # socket.SOCK_STREAM 指定 TCP 协议
        result = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)

        # 提取所有 IPv4 地址
        ipv4_addresses = []
        for res in result:
            ipv4_addresses.append(res[4][0])

        # 去重
        ipv4_addresses = list(set(ipv4_addresses))
        return ipv4_addresses[0]

    except socket.gaierror:
        return ""


def get_ipv6_addresses(domain):
    """获取域名对应的所有 IPv6 地址"""
    try:
        # socket.AF_INET6 指定只获取 IPv6 地址
        addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET6)

        # 提取 IPv6 地址并去重
        # 注意：getaddrinfo 返回的 IPv6 地址可能包含作用域ID（如 %eth0），需要处理
        ipv6_list = []
        for addr in addrinfo:
            ipv6 = addr[4][0]
            # 去除作用域ID（%后面的部分）
            if '%' in ipv6:
                ipv6 = ipv6.split('%')[0]
            ipv6_list.append(ipv6)

        return list(set(ipv6_list))[0]

    except socket.gaierror:
        return ""



class dns_resolve(QlFsMappedObject):
    def __init__(self, file):
        self.content = file
        self.seaarch_ip=""

    def write(self, data: bytes) -> int:
        if(data==""):return -1
        if(self.content == "resolve"):
            search_list = data.decode("ascii").split(" ")
            if(search_list[0]=="ipv4" or search_list[0]=="a"):self.seaarch_ip=get_ipv4_pone(search_list[1])
            elif (search_list[0]=="ipv6" or search_list[0]=="aaaa"):self.seaarch_ip=get_ipv6_addresses(search_list[1])
            elif (search_list[0]=="auto" or search_list[0]=="unspec"):
                self.seaarch_ip=get_ipv6_addresses(search_list[1])
                if(self.seaarch_ip==""):
                    self.seaarch_ip = get_ipv4_pone(search_list[1])
            else:
                self.seaarch_ip = get_ipv4_pone(search_list[0])
        if(self.content=="sever"):
            print("暂时不支持直接修改dns,别问我为什么问就是xj380操作系统开发的时候没有考虑安全性,这个操作放在现代电脑上太不安全了")
        return len(data)
    def read(self, size: int) -> bytes:
        print(self.seaarch_ip)
        if(self.content == "resolve"):return self.seaarch_ip.encode("ascii")
        if (self.content == "server"):
            return get_dns_servers()[0].encode("ascii")

    def fileno(self) -> int:
        """返回文件描述符，虚拟文件应返回 -1"""
        return -1  # 关键：表示这不是一个真实的宿主文件
    def close(self) -> int:
        self.seaarch_ip = ""
        # 可以在此执行清理工作
        return 0

