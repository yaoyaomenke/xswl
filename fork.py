#Copyright (c) 2026 yaoyaomenke
#SPDX-License-Identifier: MIT

import sys
import os
import pickle
import tempfile
import struct
from qiling import Qiling
from qiling.const import QL_VERBOSE
from unicorn.x86_const import UC_X86_INS_SYSCALL

# 导入主文件的钩子函数
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from XJ380_wine import my_raw_syscall_handler, gui_syscall, event_list, windows, windows_proc
from gui import path_tooth
from internet import search_internet_infomation, dns_resolve

# 全局变量
trampoline_ret_addr = None
allocated_memory = {}
is_inter = False
saved_regs_for_event = None


def get_export_address(elf_path, func_name):
    """从 ELF 文件获取导出函数地址"""
    from elftools.elf.elffile import ELFFile
    try:
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            symtab = elf.get_section_by_name('.symtab') or elf.get_section_by_name('.dynsym')
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym.name == func_name and sym['st_shndx'] != 'SHN_UNDEF':
                        return sym['st_value']
    except Exception as e:
        print(f"[fork.py] 获取导出地址失败: {e}")
    return None


def on_block(ql, address, size):
    """块执行钩子，处理 GUI 事件"""
    global is_inter, saved_regs_for_event, trampoline_ret_addr

    for i in windows:
        windows[i].update()

    if event_list == [] or is_inter:
        return 0

    i = event_list[0]
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

    from XJ380_wine import get_defalt_char
    if i[1] == "KeyPress":
        ql.arch.regs.rip = windows_proc[i[0]]
        if get_defalt_char(i[2].keysym) is not None:
            ql.arch.regs.rdi = 7
            ql.arch.regs.rdx = get_defalt_char(i[2].keysym)
        else:
            ql.arch.regs.rdi = 0
            ql.arch.regs.rdx = ord(i[2].char)
    elif i[1] == "mouse_button_prise":
        ql.arch.regs.rip = windows_proc[i[0]]
        if i[2].num == 1:
            ql.arch.regs.rdi = 2
        elif i[2].num == 3:
            ql.arch.regs.rdi = 3
        elif i[2].num == 2:
            ql.arch.regs.rdi = 4
        ql.arch.regs.rsi = i[2].x
        ql.arch.regs.rdx = i[2].y
    elif i[1] == "mouse_Wheel":
        ql.arch.regs.rip = windows_proc[i[0]]
        ql.arch.regs.rdx = i[2].delta
        ql.arch.regs.rdi = 5
        ql.arch.regs.rsi = (i[2].x << 32) | i[2].y
    elif i[1] == "mouse_move":
        ql.arch.regs.rip = windows_proc[i[0]]
        ql.arch.regs.rdx = 1
        ql.arch.regs.rdi = i[2].x
        ql.arch.regs.rsi = i[2].y
    elif i[1] == "button_click":
        ql.arch.regs.rip = windows_proc[i[0]]
        ql.arch.regs.rdi = 6
        ql.arch.regs.rsi = i[2]
        ql.arch.regs.rdx = 0

    del event_list[0]
    is_inter = True
    return 0


def event_return_hook(ql: Qiling):
    """事件返回钩子"""
    global saved_regs_for_event, is_inter
    if saved_regs_for_event:
        for reg, value in saved_regs_for_event.items():
            setattr(ql.arch.regs, reg, value)
        saved_regs_for_event = None
    is_inter = False


def setup_ql_for_fork(ql, target_rip):
    """设置 Qiling 实例，在 fork 系统调用处断点"""
    global trampoline_ret_addr

    # 设置断点，当执行到 fork 系统调用时检查 RIP
    def fork_breakpoint_hook(ql, address, size):
        # 检查当前是否在执行 fork 系统调用
        syscall_num = ql.arch.regs.rax
        if syscall_num == 7389:  # xapi_Fork
            # 检查调用 fork 的 RIP 是否与目标 RIP 匹配
            call_rip = ql.arch.regs.rip
            if call_rip == target_rip:
                print(f"[fork.py] 命中目标 fork 位置 RIP=0x{call_rip:x}")
                # 子进程返回 0
                ql.arch.regs.rax = 0
                # 跳过系统调用处理
                ql.skip_syscall_handler = True
                # 停止执行（或者继续）
                return

    # 注册块执行钩子来检查 fork
    ql.hook_block(fork_breakpoint_hook)

    # 注册正常的系统调用钩子
    ql.hook_insn(my_raw_syscall_handler, UC_X86_INS_SYSCALL)

    # 设置 GUI 事件钩子
    trampoline_ret_addr = ql.mem.map_anywhere(0x1000)
    ql.mem.write(trampoline_ret_addr, b'\xC3')
    ql.hook_block(on_block)
    ql.hook_address(event_return_hook, trampoline_ret_addr)


def main():
    """fork.py 主函数"""
    if len(sys.argv) < 3:
        print("用法: fork.py <程序路径> <fork_rip> [参数...]")
        print("  <程序路径>: XJ380 可执行文件路径")
        print("  <fork_rip>: 调用 xapi_Fork 时的 RIP 地址")
        print("  [参数...]: 传递给程序的参数")
        sys.exit(1)

    program_path = sys.argv[1]
    fork_rip = int(sys.argv[2], 16) if sys.argv[2].startswith('0x') else int(sys.argv[2])
    program_args = sys.argv[3:]

    print(f"[fork.py] 启动子进程模拟")
    print(f"  - 程序: {program_path}")
    print(f"  - 目标 fork RIP: 0x{fork_rip:x}")
    print(f"  - 参数: {program_args}")

    # 获取主函数地址
    main_addr = get_export_address(program_path, "_Z4mainiPPcS0_")
    if not main_addr:
        print("[fork.py] 警告: 未找到 main 函数，尝试从入口点执行")

    # 初始化 Qiling
    ql = Qiling([program_path], "./out", verbose=QL_VERBOSE.DEBUG, profile="./linux.ql")

    # 设置命令行参数
    for_exe_argv = []
    for arg in program_args:
        arg_bytes = arg.encode('utf-8') + b'\x00'
        arg_addr = ql.mem.map_anywhere(len(arg_bytes))
        ql.mem.write(arg_addr, arg_bytes)
        for_exe_argv.append(arg_addr)

    if for_exe_argv:
        argv_array = struct.pack(f"{len(for_exe_argv)}Q", *for_exe_argv)
        argv_array += b'\x00' * 8
    else:
        argv_array = b'\x00' * 8

    argv_array_addr = ql.mem.map_anywhere(len(argv_array))
    ql.mem.write(argv_array_addr, argv_array)

    ql.arch.regs.rdi = len(for_exe_argv)  # argc
    ql.arch.regs.rsi = argv_array_addr  # argv

    # 设置虚拟文件系统
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

    # 设置 fork 断点
    setup_ql_for_fork(ql, fork_rip)

    # 设置入口点蹦床
    def exit_trampoline(ql):
        print("[fork.py] 程序执行完毕")
        ql.emu_stop()

    trampoline_addr = ql.mem.map_anywhere(0x1000)
    ql.hook_address(exit_trampoline, trampoline_addr)
    ql.stack_push(trampoline_addr)

    # 如果有 main 函数地址，设置 RIP
    if main_addr:
        ql.arch.regs.rip = main_addr
        print(f"[fork.py] 设置入口点 RIP=0x{main_addr:x}")

    # 运行模拟
    print("[fork.py] 开始执行...")
    ql.run()
    print("[fork.py] 执行结束")


if __name__ == "__main__":
    main()