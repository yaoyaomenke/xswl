import subprocess
from tkinter import messagebox

from qiling import Qiling
from qiling.const import QL_VERBOSE
from unicorn.x86_const import UC_X86_INS_SYSCALL
try:
    import msvcrt
except ImportError:
    Is_linux=True
import sys
import os
import time
from gui import gui_syscall
from gui import windows
from gui import event_list
from gui import windows_proc
from internet import handle_poll_syscall
from gui import path_tooth
from internet import search_internet_infomation
from internet import dns_resolve
import shutil
import platform
trampoline_ret_addr = None
# 记录分配的内存
Is_linux=False
allocated_memory = {}
import struct
from elftools.elf.elffile import ELFFile

def get_export_address(elf_path, func_name):
    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab') or elf.get_section_by_name('.dynsym')

        if symtab:
            for sym in symtab.iter_symbols():

                if sym.name == func_name and sym['st_shndx'] != 'SHN_UNDEF':
                    return sym['st_value']
    return None
def get_defalt_char(char):
    if(char=='Escape'):return 128
    elif(char=='BackSpace'):return 0x08
    elif(char=="Tab"):return 130
    elif(char=="Return"):return 0x0A
    elif(char=="Caps_Lock"):return 132
    elif (char == "Shift_R"or char == "Shift_L"):return 133
    elif(char == "Control_L"or char=="Control_R"):return 134
    elif(char=='Alt_L'or char=="Alt_R"):return 135
    elif (char == "F1"):return 136
    elif (char == "F2"):return 137
    elif (char == "F3"):return 138
    elif (char == "F4"):return 139
    elif (char == "F5"):return 140
    elif (char == "F6"):return 141
    elif (char == "F7"):return 142
    elif (char == "F8"):return 143
    elif (char == "F9"):return 144
    elif (char == "F10"):return 145
    elif (char == "F11"):return 146
    elif (char == "F12"):return 147
    elif(char=="Num_Lock"):return 149
    elif (char == "Scroll_Lock"):return 150
    return None

def my_raw_syscall_handler(ql: Qiling):
    syscall_num = ql.arch.regs.rax
    ql.skip_syscall_handler = True
    if syscall_num == 7:  # poll 的系统调用号
        print("D")
        handle_poll_syscall(ql)
        return 0
    # Linux 系统调用：交给 Qiling
    if syscall_num <= 500:
        return 1
    elif syscall_num == 7443:  # xapi_MapMemory
        # void *xapi_MapMemory(void *addr, UINT64 size, UINT32 flags)
        addr = ql.arch.regs.rdi  # 映射起始地址（可为 NULL）
        size = ql.arch.regs.rsi  # 映射大小（字节）
        flags = ql.arch.regs.rdx  # 映射标志位

        result_addr = 0

        if size == 0:
            ql.arch.regs.rax = 0
            return

        # 计算页对齐（x86_64 页大小为 0x1000 = 4096 字节）
        page_size = 0x1000
        aligned_size = (size + page_size - 1) & ~(page_size - 1)

        # 如果 addr 为 0，让内核选择地址
        if addr == 0:
            result_addr = ql.mem.map_anywhere(aligned_size)
        else:
            # 尝试在指定地址映射
            # 需要页对齐
            aligned_addr = addr & ~(page_size - 1)
            try:
                # 先检查该区域是否已被映射
                # 如果已映射，需要先取消映射（根据实现决定，这里简化处理）
                ql.mem.map(aligned_addr, aligned_size)
                result_addr = aligned_addr
            except:
                # 映射失败，让内核选择
                result_addr = ql.mem.map_anywhere(aligned_size)

        if result_addr != 0:
            # 记录分配的内存（可选，用于后续释放）
            allocated_memory[result_addr] = aligned_size

            # 可选：根据 flags 设置内存权限
            # Qiling 的 map 默认是 rwx，如果需要更精细的控制，可以使用 ql.mem.protect()
            if flags & 0x002:  # PTE_WRITEABLE
                # 已经是可写的，无需额外操作
                pass
            if flags & 0x100:  # PTE_NO_EXECUTE
                try:
                    ql.mem.protect(result_addr, aligned_size, 1)  # 1 = PROT_READ
                except:
                    pass

        ql.arch.regs.rax = result_addr

    elif syscall_num == 7381:  # xapi_Output
        string_output = ql.mem.string(ql.arch.regs.rdi)
        print(string_output, end="")

    elif syscall_num == 7382:  # xapi_Input
        buf_ptr = ql.arch.regs.rdi
        user_input = input().split()[0]  # 读取到空格
        input_bytes = user_input.encode('utf-8') + b'\x00'
        ql.mem.write(buf_ptr, input_bytes)

    elif syscall_num == 7383:  # xapi_Getch
        if(Is_linux==True):
            char_byte = sys.stdin.read(1)
        else:
            char_byte = msvcrt.getch()
        char_value = char_byte[0] if isinstance(char_byte, bytes) else char_byte
        ql.arch.regs.rax = char_value

    elif syscall_num == 7384:  # xapi_EndLine
        print()

    elif syscall_num == 7385:  # xapi_PrintLine
        string_output = ql.mem.string(ql.arch.regs.rdi)
        print(string_output)

    elif syscall_num == 7386:  # xapi_OutputSerial
        string_output = ql.mem.string(ql.arch.regs.rdi)
        print(f"[SERIAL] {string_output}")

    elif syscall_num == 7387:  # xapi_OpenFile
        file_path = ql.mem.string(ql.arch.regs.rdi)
        full_path =path_tooth(file_path)

        try:
            with open(full_path, "rb") as f:
                file_data = f.read()

            # 分配内存并记录
            buffer_addr = ql.mem.map_anywhere(len(file_data))
            ql.mem.write(buffer_addr, file_data)
            allocated_memory[buffer_addr] = len(file_data)

            filename_bytes = file_path.encode('utf-8') + b'\x00'
            filename_addr = ql.mem.map_anywhere(len(filename_bytes))
            ql.mem.write(filename_addr, filename_bytes)
            allocated_memory[filename_addr] = len(filename_bytes)

            # 创建 XFILE 结构体
            packed = struct.pack("QQ", len(file_data), buffer_addr)
            xfile_addr = ql.mem.map_anywhere(16)
            ql.mem.write(xfile_addr, packed)
            allocated_memory[xfile_addr] = 16

            ql.arch.regs.rax = xfile_addr

        except FileNotFoundError:
            print(f"[xapi_OpenFile] 文件不存在: {full_path}")
            ql.arch.regs.rax = 0

    elif syscall_num == 7388:  # xapi_CloseFile
        fsptr = ql.arch.regs.rdi

        if fsptr != 0:
            # 读取结构体
            data = ql.mem.read(fsptr, 16)
            file_length, buffer_addr = struct.unpack("QQ", data)

            # 释放内存
            for addr in [buffer_addr, fsptr]:
                if addr != 0 and addr in allocated_memory:
                    try:
                        ql.mem.unmap(addr, allocated_memory[addr])
                        del allocated_memory[addr]
                    except:
                        pass

        ql.arch.regs.rax = 0
    # 在文件操作部分继续添加（在 xapi_CloseFile 之后）

    elif syscall_num == 7416:  # xapi_SearchFile
        path_ptr = ql.arch.regs.rdi  # WSTR path
        count_ptr = ql.arch.regs.rsi  # UINT32 *count
        dir_ptr = ql.arch.regs.rdx  # DirNode *dir (256大小数组)

        # 读取路径
        path = ql.mem.string(path_ptr)
        full_path = path_tooth(path)

        # 定义 DirNode 结构体大小: filename[256] + length(8) + filetype(8) = 272字节
        DIRNODE_SIZE = 256 + 8 + 8  # 272

        try:
            entries = []
            # 获取目录下的所有文件和子目录
            for entry in os.scandir(full_path):
                if entry.is_file():
                    filetype = 0
                    length = entry.stat().st_size
                elif entry.is_dir():
                    filetype = 1
                    length = 0
                else:
                    continue  # 忽略其他类型

                # 文件名最多255字符（留1字节给null，但文档没要求null，我们填充完整256字节）
                filename_bytes = entry.name.encode('utf-8')
                if len(filename_bytes) > 255:
                    filename_bytes = filename_bytes[:255]  # 截断
                # 固定256字节，不足部分用0填充
                filename_fixed = filename_bytes.ljust(256, b'\x00')

                entries.append({
                    'filename': filename_fixed,
                    'length': length,
                    'filetype': filetype
                })

            count = len(entries)
            if count > 255:
                count = 256  # 超出255时 count 设置为256（文档规定）

            # 写入 count
            ql.mem.write(count_ptr, struct.pack("I", count))

            # 写入 DirNode 数组（最多256项，但只写入实际有效的项）
            for i, entry in enumerate(entries[:255]):  # 最多写入255项
                offset = i * DIRNODE_SIZE
                # 写入 filename (256字节)
                ql.mem.write(dir_ptr + offset, entry['filename'])
                # 写入 length (8字节)
                ql.mem.write(dir_ptr + offset + 256, struct.pack("Q", entry['length']))
                # 写入 filetype (8字节)
                ql.mem.write(dir_ptr + offset + 256 + 8, struct.pack("Q", entry['filetype']))

        except FileNotFoundError:
            # 找不到路径，count 设置为 404
            ql.mem.write(count_ptr, struct.pack("I", 404))

        except Exception as e:
            print(f"[xapi_SearchFile] 错误: {e}")
            ql.mem.write(count_ptr, struct.pack("I", 0))

    elif syscall_num == 7425:  # xapi_Makedir
        print("d")
        path_ptr = ql.arch.regs.rdi
        path = ql.mem.string(path_ptr)
        full_path = path_tooth(path)

        try:
            os.makedirs(full_path, exist_ok=False)
        except FileExistsError:
            print(f"[xapi_Makedir] 目录已存在: {full_path}")
        except Exception as e:
            print(f"[xapi_Makedir] 错误: {e}")

    elif syscall_num == 7420:  # xapi_CreateFile
        filename_ptr = ql.arch.regs.rdi
        filename = ql.mem.string(filename_ptr)
        full_path = path_tooth(filename)

        try:
            # 创建空文件
            with open(full_path, "wb") as f:
                pass  # 只创建不写入内容
        except Exception as e:
            print(f"[xapi_CreateFile] 错误: {e}")

    elif syscall_num == 7421:  # xapi_DeleteFile
        path_ptr = ql.arch.regs.rdi
        path = ql.mem.string(path_ptr)
        full_path = path_tooth(path)

        try:
            if os.path.isfile(full_path):
                os.remove(full_path)
            else:
                print(f"[xapi_DeleteFile] 不是文件或不存在: {full_path}")
        except Exception as e:
            print(f"[xapi_DeleteFile] 错误: {e}")

    elif syscall_num == 7422:  # xapi_RenameFile
        old_path_ptr = ql.arch.regs.rdi
        new_path_ptr = ql.arch.regs.rsi
        old_path = ql.mem.string(old_path_ptr)
        new_path = ql.mem.string(new_path_ptr)
        full_old = path_tooth(old_path)
        full_new = path_tooth(new_path)

        try:
            os.rename(full_old, full_new)
        except Exception as e:
            print(f"[xapi_RenameFile] 错误: {e}")

    elif syscall_num == 7423:  # xapi_ReadFile
        filename_ptr = ql.arch.regs.rdi  # WSTR filename
        buffer_ptr = ql.arch.regs.rsi  # char* buffer
        size = ql.arch.regs.rdx  # UINT64 size
        offset = ql.arch.regs.r10  # UINT64 offset (注意第4个参数使用 r10)

        filename = ql.mem.string(filename_ptr)
        full_path = path_tooth(filename)

        try:
            with open(full_path, "rb") as f:
                f.seek(offset)
                data = f.read(size)
                actual_read = len(data)
                # 写入 guest 缓冲区
                ql.mem.write(buffer_ptr, data)
            # 返回值无，但可能需要设置 rax 为实际读取字节数？文档说 void，忽略
            print(f"[xapi_ReadFile] 读取 {actual_read}/{size} 字节从 {full_path} 偏移 {offset}")
        except Exception as e:
            print(f"[xapi_ReadFile] 错误: {e}")

    elif syscall_num == 7424:  # xapi_WriteFile
        filename_ptr = ql.arch.regs.rdi  # WSTR filename
        buffer_ptr = ql.arch.regs.rsi  # char* buffer
        size = ql.arch.regs.rdx  # UINT64 size
        offset = ql.arch.regs.r10  # UINT64 offset

        filename = ql.mem.string(filename_ptr)
        full_path =path_tooth(filename)

        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            # 以 r+b 模式打开，如果不存在则创建
            with open(full_path, "r+b") as f:
                f.seek(offset)
                # 从 guest 内存读取数据
                data = ql.mem.read(buffer_ptr, size)
                f.write(data)
        except FileNotFoundError:
            # 文件不存在，创建并写入
            try:
                with open(full_path, "wb") as f:
                    f.seek(offset)
                    data = ql.mem.read(buffer_ptr, size)
                    f.write(data)
                print(f"[xapi_WriteFile] 创建并写入 {size} 字节到 {full_path}")
            except Exception as e:
                print(f"[xapi_WriteFile] 错误: {e}")
        except Exception as e:
            print(f"[xapi_WriteFile] 错误: {e}")
    elif syscall_num==7444:
        print("r")
        filename_ptr = ql.arch.regs.rdi
        filename = ql.mem.string(filename_ptr)
        full_path = path_tooth(filename)
        shutil.rmtree(full_path)
    # ==================== 3.4 进程（暂不实现，仅占位） ====================
    elif syscall_num == 7389:  # xapi_Fork
        print("[xapi_Fork] 未实现，返回 -1")
        ql.arch.regs.rax = -1

    elif syscall_num == 7390:  # xapi_Execve
        print("[xapi_Execve] 未实现，返回 -1")
        ql.arch.regs.rax = -1

    # ==================== 3.5 获取当前信息 ====================
    elif syscall_num == 7391:  # xapi_GetSystemVersion
        # void xapi_GetSystemVersion(WSTR version)
        version_str = "XJ380 OS Compatible Layer 1.0"
        buf_ptr = ql.arch.regs.rdi
        # 写入 UTF-8 字符串（含 null 结尾）
        data = version_str.encode('utf-8') + b'\x00'
        ql.mem.write(buf_ptr, data)

    elif syscall_num == 7412:  # xapi_GetTime
        # UINT64 xapi_GetTime(void)  返回从1980-01-01 00:00:00 开始的秒数

        EPOCH1980 = 315532800  # 1970-01-01 到 1980-01-01 的秒数
        now = int(time.time()) - EPOCH1980
        ql.arch.regs.rax = now


    elif syscall_num == 7413:  # xapi_GetCurrentUser (增强版)
        user_info_ptr = ql.arch.regs.rdi
        if user_info_ptr == 0:
            print("[xapi_GetCurrentUser] 警告: 传入空指针")
            return
        # UserTpe 枚举映射
        USER_TYPE_MAP = {
            "Root": 0,
            "System": 1,
            "Admin": 2,
            "Visitor": 3,
            "Custom": 4
        }
        # 默认值
        username = username = os.getlogin()
        user_type = 2  # Admin
        # 写入用户名（64字节）
        name_bytes = username.encode('utf-8')
        if len(name_bytes) > 63:
            name_bytes = name_bytes[:63]
        name_fixed = name_bytes + b'\x00' * (64 - len(name_bytes))
        ql.mem.write(user_info_ptr, name_fixed)
        # 写入用户类型（4字节）
        ql.mem.write(user_info_ptr + 64, struct.pack("I", user_type))
        # 函数是 void，无需返回值


    elif syscall_num == 7433:  # xapi_GetTimeX
        tm_ptr = ql.arch.regs.rdi
        if tm_ptr == 0:
            return
        now = time.localtime()
        struct_data = struct.pack(
            'iiiiiiiii',
            now.tm_sec,  # 秒 [0,59]
            now.tm_min,  # 分 [0,59]
            now.tm_hour,  # 时 [0,23]
            now.tm_mday,  # 日 [1,31]
            now.tm_mon + 1,  # 月 [1,12]
            now.tm_year,  # 年（从 1900 开始）
            (now.tm_wday + 1) % 7 + 1,  # 星期几（星期日=1）
            now.tm_yday,  # 年中的第几天 [0,365]
            now.tm_isdst  # 夏令时标志
        )
        ql.mem.write(tm_ptr, struct_data)


    elif syscall_num == 7434:  # xapi_GetCpuModel
        # void xapi_GetCpuModel(WSTR version)
        cpu_model = platform.processor() or "Unknown CPU"
        buf_ptr = ql.arch.regs.rdi
        data = cpu_model.encode('utf-8') + b'\x00'
        ql.mem.write(buf_ptr, data)

    elif syscall_num == 7435:  # xapi_GetMemorySize
        # UINT64 xapi_GetMemorySize(void)  返回内存大小（MB）
        try:
            import psutil
            total_mem = psutil.virtual_memory().total // (1024 * 1024)
        except ImportError:
            # 没有 psutil 时尝试使用 os.sysconf
            try:
                # 对于 Linux 可用，Windows 上用 GlobalMemoryStatusEx 更复杂
                total_mem = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') // (1024 * 1024)
            except:
                total_mem = 2048  # 默认 2GB
        ql.arch.regs.rax = total_mem

    # ==================== 3.6 系统消息及服务 ====================
    elif syscall_num == 7428:  # xapi_Broken
        # void xapi_Broken(WSTR broken_info)
        info_ptr = ql.arch.regs.rdi
        if info_ptr != 0:
            info = ql.mem.string(info_ptr)
            print(f"[xapi_Broken] 程序崩溃: {info}")
        else:
            print("[xapi_Broken] 程序崩溃 (无详细信息)")

        messagebox.showerror("程序崩溃", "此程序崩溃,原因未知。")

    elif syscall_num == 7429:  # xapi_SendAppMessage
        # void xapi_SendAppMessage(WSTR title, WSTR text)
        title_ptr = ql.arch.regs.rdi
        text_ptr = ql.arch.regs.rsi
        title = ql.mem.string(title_ptr) if title_ptr != 0 else ""
        text = ql.mem.string(text_ptr) if text_ptr != 0 else ""
        # 弹出提示框
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, text, title, 0x40)  # 信息图标
        except:
            pass

    elif syscall_num == 7430:  # xapi_Sleep
        # void xapi_Sleep(UINT64 ms)
        ms = ql.arch.regs.rdi
        time.sleep(ms / 1000.0)

    elif syscall_num == 7439:  # xapi_Run
        # void xapi_Run(WSTR path)
        path_ptr = ql.arch.regs.rdi
        path = ql.mem.string(path_ptr).replace("//","/")
        path=path_tooth(path)
        path=os.path.abspath(path)
        if(Is_linux==True):
            subprocess.call(['xdg-open', path])
        else:
            try:
                os.startfile(path)
            except Exception as e:
                print(f" 启动失败: {e}")

    # ==================== 3.7 内存 ====================
    elif syscall_num == 7441:  # xapi_AllocateMemory
        # void *xapi_AllocateMemory(UINT64 size)
        size = ql.arch.regs.rdi
        if size == 0:
            ql.arch.regs.rax = 0
        else:
            # 使用 Qiling 动态分配内存（页对齐，但大小可能超过页）
            addr = ql.mem.map_anywhere(size)
            if addr != 0:
                allocated_memory[addr] = size
            ql.arch.regs.rax = addr

    elif syscall_num == 7442:  # xapi_FreeMemory
        # void xapi_FreeMemory(void *ptr)
        ptr = ql.arch.regs.rdi
        if ptr in allocated_memory:
            size = allocated_memory[ptr]
            try:
                ql.mem.unmap(ptr, size)
                del allocated_memory[ptr]
            except Exception as e:
                print(f"[xapi_FreeMemory] 释放失败: {e}")
        else:
            print(f"[xapi_FreeMemory] 警告: 未找到地址 {hex(ptr)} 的分配记录")

    # ========== 未实现的系统调用（占位） ==========
    else:
        gui_syscall(ql)
    #============剩下的就是gui的事情了===============

    return 0

if(len(sys.argv)==1):
    print("可执行文件路径这种其他参数跑哪儿去了?")
    exit(0)
# 初始化 Qiling
ql = Qiling([sys.argv[1]], "./out", verbose=QL_VERBOSE.DEBUG,profile="./linux.ql")
# 设置入口点
main_addr =get_export_address(sys.argv[1], "_Z4mainiPPcS0_")
#把参数放好
for_exe_argv=[]
for i in sys.argv[2:]:
    # 分配内存存储参数字符串（包含 null 结尾）
    arg_bytes = i.encode('utf-8') + b'\x00'
    arg_addr = ql.mem.map_anywhere(len(arg_bytes))
    ql.mem.write(arg_addr, arg_bytes)
    for_exe_argv.append(arg_addr)

# 将参数指针数组打包成连续的 8 字节地址
if for_exe_argv:
    argv_array = struct.pack(f"{len(for_exe_argv)}Q", *for_exe_argv)
    argv_array += b'\x00' * 8  # 添加一个 NULL 指针作为结束标记（可选）
else:
    argv_array = b'\x00' * 8  # 无参数时只放 NULL 指针


is_inter=False
saved_regs_for_event = None

# 分配内存并写入参数指针数组
argv_array_addr = ql.mem.map_anywhere(len(argv_array))
ql.mem.write(argv_array_addr, argv_array)

ql.arch.regs.rdi = len(for_exe_argv)  # argc
ql.arch.regs.rsi = argv_array_addr    # argv
print(f"[+] main 函数地址: 0x{main_addr:x}")
def exit_trampoline(ql):
    """main 返回后执行这里，然后停止模拟"""
    print("[+] main 返回，模拟结束")
    ql.emu_stop()
def on_block(ql, address, size):
    global is_inter,saved_regs_for_event,trampoline_ret_addr
    for i in windows:
        windows[i].update()
    if(event_list==[]or is_inter==True):
        return 0
    i=event_list[0]
    saved_regs_for_event = {
        'rax': ql.arch.regs.rax,
        'rbx': ql.arch.regs.rbx,
        'rcx': ql.arch.regs.rcx,
        'rdx': ql.arch.regs.rdx,
        'rsi': ql.arch.regs.rsi,
        'rdi': ql.arch.regs.rdi,
        'rbp': ql.arch.regs.rbp,
        'r8': ql.arch.regs.r8,
        'r9': ql.arch.regs.r9,
        'r10': ql.arch.regs.r10,
        'r11': ql.arch.regs.r11,
        'r12': ql.arch.regs.r12,
        'r13': ql.arch.regs.r13,
        'r14': ql.arch.regs.r14,
        'r15': ql.arch.regs.r15,
        'eflags': ql.arch.regs.eflags,
    }
    ql.stack_push(ql.arch.regs.rip)
    ql.stack_push(trampoline_ret_addr)
    if i[1]=="KeyPress":
        ql.arch.regs.rip = windows_proc[i[0]]
        if(get_defalt_char(i[2].keysym)!=None):
            ql.arch.regs.rdi = 7
            ql.arch.regs.rdx = get_defalt_char(i[2].keysym)
        else:
            ql.arch.regs.rdi = 0
            ql.arch.regs.rdx=ord(i[2].char)

    elif(i[1]=="mouse_button_prise"):
        ql.arch.regs.rip = windows_proc[i[0]]
        if(i[2].num==1):
            ql.arch.regs.rdi = 2
        elif (i[2].num == 3):
            ql.arch.regs.rdi = 3
        elif (i[2].num == 2):
            ql.arch.regs.rdi = 4
        ql.arch.regs.rsi = i[2].x
        ql.arch.regs.rdx = i[2].y
    elif(i[1]=="mouse_Wheel"):
        ql.arch.regs.rip = windows_proc[i[0]]
        ql.arch.regs.rdx = i[2].delta
        ql.arch.regs.rdi = 5
        ql.arch.regs.rsi=( i[2].x<< 32) | i[2].y
    elif(i[1]=="mouse_move"):
        ql.arch.regs.rip = windows_proc[i[0]]
        ql.arch.regs.rdx = 1
        ql.arch.regs.rdi = i[2].x
        ql.arch.regs.rsi=i[2].y
    elif i[1] == "button_click":
        ql.arch.regs.rip = windows_proc[i[0]]
        ql.arch.regs.rdi = 6      # MSG_CRL 消息类型
        ql.arch.regs.rsi = i[2]    # 控件识别码 CRLid
        ql.arch.regs.rdx = 0       # 控件数据（按钮无额外数据）

    del event_list[0]
    is_inter=True
    return 0;
# 在栈上分配一个位置，写入 trampoline 的地址
trampoline_addr = ql.mem.map_anywhere(0x1000) # 映射一页内存
ql.hook_block(on_block)
ql.hook_address(exit_trampoline, trampoline_addr)

# 修改栈顶的返回地址为 trampoline_addr
# 注意：不同架构的栈指针寄存器不同，这里以 x64 为例
ql.stack_push(trampoline_addr)
# 注册系统调用钩子
ql.hook_insn(my_raw_syscall_handler, UC_X86_INS_SYSCALL)


trampoline_ret_addr= ql.mem.map_anywhere(0x1000)

# 写入 ret 指令 (0xC3)
ql.mem.write(trampoline_ret_addr, b'\xC3')



def event_return_hook(ql: Qiling):
    global saved_regs_for_event, in_event_handler,is_inter
    if saved_regs_for_event:
        # 恢复所有通用寄存器（除了 rsp，因为栈已经平衡）
        for reg, value in saved_regs_for_event.items():
            setattr(ql.arch.regs, reg, value)
        saved_regs_for_event = None
        in_event_handler = False
    # 注意：不修改 rip，执行完钩子后会继续执行蹦床里的 ret 指令
    is_inter=False

ql.hook_address(event_return_hook, trampoline_ret_addr)
virtual_file = search_internet_infomation("status")
ql.add_fs_mapper('/run/NetworkManager/status', virtual_file)
virtual_file = search_internet_infomation("state")
ql.add_fs_mapper('state', virtual_file)
virtual_file = search_internet_infomation("ipv4")
ql.add_fs_mapper('/run/NetworkManager/ipv4', virtual_file)
virtual_file = search_internet_infomation("ipv6")
ql.add_fs_mapper('/run/NetworkManager/ipv6', virtual_file)
dns = dns_resolve("resolve")
ql.add_fs_mapper('/run/dns/resolve', dns)
dns_find = dns_resolve("server")
ql.add_fs_mapper('/run/dns/server', dns_find)
# 运行
ql.run()


