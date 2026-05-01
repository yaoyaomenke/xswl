#Copyright (c) 2026 yaoyaomenke
#SPDX-License-Identifier: MIT


# from qiling import Qiling
# from ctypes import *
# import msvcrt
# import struct
# import os
# import time
# import tkinter
# windows = {}
# win_handel = 1
# def gui_syscall(ql: Qiling):
#     global win_handel
#     syscall_num = ql.arch.regs.rax
#     if syscall_num ==  7392:# create window
#         windows[win_handel]=tkinter.Tk()
#         ql.mem.write(ql.arch.regs.rdi,win_handel.to_bytes(8,'little'))
#         print(win_handel)
#         windows[win_handel].title(ql.mem.string(int.from_bytes(ql.mem.read(ql.arch.regs.rsi + 8, 8), byteorder='little')))
#         windows[win_handel].geometry(str(int.from_bytes(ql.mem.read(ql.arch.regs.rsi + 0, 4),signed=False,byteorder='little'))+"x"+str(int.from_bytes(ql.mem.read(ql.arch.regs.rsi + 4, 4),signed=False,byteorder='little')))
#         windows[win_handel].resizable(False, False)
#         windows[win_handel].update()
#         win_handel+=1
#         ql.arch.regs.rax = 0
#     elif syscall_num==7393:# xapi_SetWindowTitle();
#         handel=ql.arch.regs.rdi
#         windows[handel].title(ql.mem.string(ql.arch.regs.rsi))
#     elif syscall_num==7394:#xapi_CloseWindow
#         handel = ql.arch.regs.rdi
#         windows.pop(handel)
#         ql.arch.regs.rax = 0
#     elif syscall_num==7395:#xapi_SetIcon();
#         handel = ql.arch.regs.rdi
#         windows[handel].iconbitmap("./out"+ql.mem.string(ql.arch.regs.rsi))
#         ql.arch.regs.rax = 0
#     elif syscall_num==7426:
#         handel = ql.arch.regs.rdi
#         width=windows[handel].winfo_width()
#         height=windows[handel].winfo_height()
#         ql.mem.write(ql.arch.regs.rsi, width.to_bytes(8, 'little', signed=False))
#         ql.mem.write(ql.arch.regs.rdx, height.to_bytes(8, 'little', signed=False))
#     ql.arch.regs.rax = 0
#
#
#     return
import io
import sys

from qiling import Qiling
import struct
import tempfile
import tkinter.font as tkfont
import atexit
import os
import cairosvg
import tkinter as tk
from PIL import Image, ImageTk, ImageGrab, ImageOps  # 需要 pip install Pillow
def path_tooth(path:str):
    if(path[0]=="/"):
        return "./out"+path
    else:
        return "./out/"+path
windows_proc={}

windows = {}
win_handel = 1
event_list=[]


def parse_xj380_color(color: int) -> str:
    r = (color >> 24) & 0xFF
    g = (color >> 16) & 0xFF
    b = (color >> 8) & 0xFF

    return f"#{r:02x}{g:02x}{b:02x}"
def gui_syscall(ql: Qiling):
    global win_handel
    syscall_num = ql.arch.regs.rax

    # ---------- 4.1 创建图形化应用程序 ----------
    if syscall_num == 7392:  # xapi_CreateWindow
        # 参数: rdi = HDLE* handle, rsi = XWINDOW* xwin
        handle_ptr = ql.arch.regs.rdi
        xwin_ptr = ql.arch.regs.rsi
        print("d")

        # 读取 XWINDOW 结构体: width(4), height(4), title_ptr(8), sets(1)
        width = struct.unpack("I", ql.mem.read(xwin_ptr, 4))[0]
        height = struct.unpack("I", ql.mem.read(xwin_ptr + 4, 4))[0]
        title_ptr = struct.unpack("Q", ql.mem.read(xwin_ptr + 8, 8))[0]
        sets = ql.mem.read(xwin_ptr + 16, 1)[0]
        title = ql.mem.string(title_ptr) if title_ptr != 0 else ""

        # 创建窗口
        win = tk.Tk()
        # 在 win = tk.Tk() 之后，win.canvas = canvas 之后添加
        win.buttons = {}  # CRLid -> button对象
        win.right_menu = None  # 右键菜单对象
        win.right_menu_items = []  # 存储 (CRLid, text) 用于重建
        win.title(title)
        win.geometry(f"{width}x{height}")
        win.resizable(False, False)
        if sets == 1:          # XWIN_FRAME_OFF
            win.overrideredirect(True)
        elif sets == 2:        # XWIN_FULL_SCR
            win.attributes('-fullscreen', True)
        win.protocol("WM_DELETE_WINDOW", on_user_clothing)

        # 创建画布
        canvas = tk.Canvas(win, width=width, height=height, bg='white')
        canvas.pack(fill=tk.BOTH, expand=True)
        win.canvas = canvas   # 附加 canvas 属性

        # 保存窗口
        windows[win_handel] = win
        windows[win_handel].update()
        # 将句柄写回 guest 内存
        ql.mem.write(handle_ptr, struct.pack("Q", win_handel))
        win_handel += 1
        ql.arch.regs.rax = 0

    elif syscall_num == 7393:  # xapi_SetWindowTitle
        handle = ql.arch.regs.rdi
        title_ptr = ql.arch.regs.rsi
        title = ql.mem.string(title_ptr)
        win = windows.get(handle)
        if win:
            win.title(title)
        ql.arch.regs.rax = 0


    elif syscall_num == 7394:  # xapi_CloseWindow
        handle = ql.arch.regs.rdi
        win = windows.pop(handle, None)
        if win:
            # 清理按钮
            for btn in win.buttons.values():
                btn.destroy()
            win.buttons.clear()
            # 清理右键菜单
            if win.right_menu:
                win.right_menu.destroy()
            win.destroy()
        ql.arch.regs.rax = 0



    elif syscall_num == 7395:  # xapi_SetIcon
        handle = ql.arch.regs.rdi
        path_ptr = ql.arch.regs.rsi
        path = ql.mem.string(path_ptr)
        full_path = path_tooth(path)
        win = windows.get(handle)
        if win and os.path.exists(full_path):
            try:
                if sys.platform == "win32":
                    # Windows: 直接使用 iconbitmap
                    if full_path.lower().endswith('.ico'):
                        win.iconbitmap(full_path)
                    else:
                        img = Image.open(full_path)
                        img = img.resize((32, 32), Image.Resampling.LANCZOS)
                        temp_ico = tempfile.NamedTemporaryFile(suffix='.ico', delete=False)
                        temp_path = temp_ico.name
                        temp_ico.close()
                        img.save(temp_path, format='ICO', sizes=[(32, 32)])
                        win.iconbitmap(temp_path)
                        atexit.register(lambda: os.unlink(temp_path) if os.path.exists(temp_path) else None)
                else:
                    # Linux/Mac: 使用 iconphoto 方法
                    img = Image.open(full_path)
                    # 调整到合适大小
                    img = img.resize((64, 64), Image.Resampling.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    # 保存引用防止被垃圾回收
                    if not hasattr(win, '_icon_images'):
                        win._icon_images = []
                    win._icon_images.append(photo)
                    win.iconphoto(True, photo)
            except Exception as e:
                print(f"[xapi_SetIcon] 设置图标失败 ({full_path}): {e}")
        ql.arch.regs.rax = 0

    elif syscall_num == 7426:  # xapi_GetWindowSize
        handle = ql.arch.regs.rdi
        width_ptr = ql.arch.regs.rsi
        height_ptr = ql.arch.regs.rdx
        win = windows.get(handle)
        if win:
            win.update_idletasks()
            w = win.winfo_width()
            h = win.winfo_height()
            ql.mem.write(width_ptr, struct.pack("Q", w))
            ql.mem.write(height_ptr, struct.pack("Q", h))
        ql.arch.regs.rax = 0

    # ---------- 4.2 绘图 ----------
    elif syscall_num == 7396:  # xapi_DrawPoint
        handle = ql.arch.regs.rdi
        x = ql.arch.regs.rsi
        y = ql.arch.regs.rdx
        color = ql.arch.regs.r10
        win = windows.get(handle)
        if win and hasattr(win, 'canvas'):
            color_hex = parse_xj380_color(color)
            win.canvas.create_oval(x-1, y-1, x+1, y+1, fill=color_hex, outline=color_hex)
        ql.arch.regs.rax = 0

    elif syscall_num == 7397:  # xapi_DrawLine
        handle = ql.arch.regs.rdi
        x1, y1, x2, y2, color = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8, ql.arch.regs.r9
        win = windows.get(handle)
        if win and hasattr(win, 'canvas'):
            color_hex = parse_xj380_color(color)
            win.canvas.create_line(x1, y1, x2, y2, fill=color_hex)
        ql.arch.regs.rax = 0

    elif syscall_num == 7398:  # xapi_DrawRect (空心)
        handle = ql.arch.regs.rdi
        x1, y1, x2, y2, color = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8, ql.arch.regs.r9
        win = windows.get(handle)
        if win and hasattr(win, 'canvas'):
            color_hex = parse_xj380_color(color)
            win.canvas.create_rectangle(x1, y1, x2, y2, outline=color_hex)
        ql.arch.regs.rax = 0

    elif syscall_num == 7399:  # xapi_DrawRect_Fill (实心)
        handle = ql.arch.regs.rdi
        x1, y1, x2, y2, color = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8, ql.arch.regs.r9
        win = windows.get(handle)
        if win and hasattr(win, 'canvas'):
            color_hex = parse_xj380_color(color)
            win.canvas.create_rectangle(x1, y1, x2, y2, fill=color_hex, outline=color_hex)
        ql.arch.regs.rax = 0

    elif syscall_num == 7400:  # xapi_DrawCircle (空心)
        handle = ql.arch.regs.rdi
        x, y, r, color = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8
        win = windows.get(handle)
        if win and hasattr(win, 'canvas'):
            color_hex = parse_xj380_color(color)
            win.canvas.create_oval(x-r, y-r, x+r, y+r, outline=color_hex)
        ql.arch.regs.rax = 0

    elif syscall_num == 7401:  # xapi_DrawCircle_Fill (实心)
        handle = ql.arch.regs.rdi
        x, y, r, color = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8
        win = windows.get(handle)
        if win and hasattr(win, 'canvas'):
            color_hex = parse_xj380_color(color)
            win.canvas.create_oval(x-r, y-r, x+r, y+r, fill=color_hex, outline=color_hex)
        ql.arch.regs.rax = 0

    elif syscall_num == 7402:  # xapi_DrawText (普通)
        handle = ql.arch.regs.rdi
        x, y, str_ptr, size, color = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8, ql.arch.regs.r9
        text = ql.mem.string(str_ptr)
        win = windows.get(handle)
        if win and hasattr(win, 'canvas'):
            color_hex = parse_xj380_color(color)
            font = ('Arial', size)
            win.canvas.create_text(x, y, text=text, fill=color_hex, font=font, anchor='nw')
        ql.arch.regs.rax = 0

    elif syscall_num == 7415:  # xapi_DrawSWText (等宽)
        handle = ql.arch.regs.rdi
        x, y, str_ptr, color = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8
        text = ql.mem.string(str_ptr)
        win = windows.get(handle)
        if win and hasattr(win, 'canvas'):
            color_hex = parse_xj380_color(color)
            font = ('Courier', 9)
            win.canvas.create_text(x, y, text=text, fill=color_hex, font=font, anchor='nw')
        ql.arch.regs.rax = 0

    elif syscall_num == 7431:  # xapi_CalcTextWidth
        str_ptr = ql.arch.regs.rdi
        size = ql.arch.regs.rsi
        text = ql.mem.string(str_ptr)
        from tkinter.font import Font
        f = Font(family='Arial', size=size)
        width = f.measure(text)
        ql.arch.regs.rax = width

    # ---------- 4.3 插入图片 ----------
    elif syscall_num == 7403:  # xapi_DrawBMP
        handle = ql.arch.regs.rdi
        x, y, w, h, path_ptr = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8, ql.arch.regs.r9
        path = ql.mem.string(path_ptr)
        full_path = path_tooth(path)
        win = windows.get(handle)
        if win and hasattr(win, 'canvas') and os.path.exists(full_path):
            try:
                img = Image.open(full_path)
                img = img.resize((w, h), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                # 保持引用防止被垃圾回收
                if not hasattr(win.canvas, 'images'):
                    win.canvas.images = []
                win.canvas.images.append(photo)
                win.canvas.create_image(x, y, image=photo, anchor='nw')
            except Exception as e:
                print(f"[xapi_DrawBMP] 错误: {e}")
        ql.arch.regs.rax = 0

    elif syscall_num == 7404:  # xapi_DrawPNG
        # 与 BMP 相同，PIL 自动处理格式
        handle = ql.arch.regs.rdi
        x, y, w, h, path_ptr = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8, ql.arch.regs.r9
        path = ql.mem.string(path_ptr)
        full_path = path_tooth(path)
        win = windows.get(handle)
        if win and hasattr(win, 'canvas') and os.path.exists(full_path):
            try:
                img = Image.open(full_path)
                img = img.resize((w, h), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                if not hasattr(win.canvas, 'images'):
                    win.canvas.images = []
                win.canvas.images.append(photo)
                win.canvas.create_image(x, y, image=photo, anchor='nw')
            except Exception as e:
                print(f"[xapi_DrawPNG] 错误: {e}")
        ql.arch.regs.rax = 0
    elif syscall_num==7447:
        handel=ql.arch.regs.rdi
        draw_x=ql.arch.regs.rsi
        draw_y=ql.arch.regs.rdx
        draw_width=ql.arch.regs.r10
        name=ql.arch.regs.r8
        path = ql.mem.string(name)
        enable_trans=ql.arch.regs.r9
        win = windows.get(handel)
        png_data = cairosvg.svg2png(
            url=f"./out/system/resources/svg/{path}.svg",
            output_width=draw_width,
        )
        img = Image.open(io.BytesIO(png_data))
        if(enable_trans==1):
            img=ImageOps.invert(img)
        photo = ImageTk.PhotoImage(img)
        if not hasattr(win.canvas, 'images'):
            win.canvas.images = []
        win.canvas.images.append(photo)
        win.canvas.create_image(draw_x, draw_y, image=photo, anchor='nw')


    elif syscall_num == 7419:  # xapi_DrawPicture
        # 通用图片，同样使用 PIL
        handle = ql.arch.regs.rdi
        x, y, w, h, path_ptr = ql.arch.regs.rsi, ql.arch.regs.rdx, ql.arch.regs.r10, ql.arch.regs.r8, ql.arch.regs.r9
        path = ql.mem.string(path_ptr)
        full_path = path_tooth(path)
        win = windows.get(handle)
        if win and hasattr(win, 'canvas') and os.path.exists(full_path):
            try:
                img = Image.open(full_path)
                img = img.resize((w, h), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                if not hasattr(win.canvas, 'images'):
                    win.canvas.images = []
                win.canvas.images.append(photo)
                win.canvas.create_image(x, y, image=photo, anchor='nw')
            except Exception as e:
                print(f"[xapi_DrawPicture] 错误: {e}")
        ql.arch.regs.rax = 0

    elif syscall_num == 7440:  # xapi_GetPicSize
        width_ptr = ql.arch.regs.rdi
        height_ptr = ql.arch.regs.rsi
        path_ptr = ql.arch.regs.rdx
        path = ql.mem.string(path_ptr)
        full_path = path_tooth(path)
        if os.path.exists(full_path):
            try:
                img = Image.open(full_path)
                w, h = img.size
                ql.mem.write(width_ptr, struct.pack("I", w))
                ql.mem.write(height_ptr, struct.pack("I", h))
            except Exception as e:
                print(f"[xapi_GetPicSize] 错误: {e}")
        else:
            print(f"[xapi_GetPicSize] 文件不存在: {full_path}")
        ql.arch.regs.rax = 0
    elif syscall_num==7409:
        handle = ql.arch.regs.rdi
        win = windows.get(handle)
        win.update()
    elif syscall_num==7405:
        handle = ql.arch.regs.rdi
        porc = ql.arch.regs.rsi
        win = windows.get(handle)
        event=create_handler(handle)
        win.bind_all("<KeyPress>", event)
        win.bind_all("<ButtonPress>", event)
        win.bind_all("<Motion>", event)
        win.bind_all("<MouseWheel>", event)
        windows_proc[handle]=porc
    # ========== 4.5 framebuffer 操作 ==========
    elif syscall_num == 7406:  # xapi_ReadBuffer (RGB)
        handle = ql.arch.regs.rdi
        x = ql.arch.regs.rsi
        y = ql.arch.regs.rdx
        width = ql.arch.regs.r10
        height = ql.arch.regs.r8
        buffer_ptr = ql.arch.regs.r9

        win = windows.get(handle)
        if not win or not hasattr(win, 'canvas'):
            ql.arch.regs.rax = -1
            return

        # 获取窗口在屏幕上的绝对位置
        win.update_idletasks()
        abs_x = win.winfo_rootx() + x
        abs_y = win.winfo_rooty() + y

        # 抓取指定区域
        try:
            img = ImageGrab.grab(bbox=(abs_x, abs_y, abs_x + width, abs_y + height))
            img = img.convert('RGB')
            pixels = img.tobytes()   # 每像素3字节 (R,G,B)
            # 写入 guest 内存
            ql.mem.write(buffer_ptr, pixels)
            ql.arch.regs.rax = 0
        except Exception as e:
            print(f"[xapi_ReadBuffer] 错误: {e}")
            ql.arch.regs.rax = -1

    elif syscall_num == 7407:  # xapi_WriteBuffer (RGB)
        handle = ql.arch.regs.rdi
        x = ql.arch.regs.rsi
        y = ql.arch.regs.rdx
        width = ql.arch.regs.r10
        height = ql.arch.regs.r8
        buffer_ptr = ql.arch.regs.r9

        win = windows.get(handle)
        if not win or not hasattr(win, 'canvas'):
            ql.arch.regs.rax = -1
            return

        # 从 guest 读取像素数据 (RGB 连续)
        data_size = width * height * 3
        pixels = ql.mem.read(buffer_ptr, data_size)
        if len(pixels) != data_size:
            print(f"[xapi_WriteBuffer] 读取内存失败")
            ql.arch.regs.rax = -1
            return

        # 在 canvas 上逐个像素绘制 (用矩形或点，效率较低，但实现简单)
        canvas = win.canvas
        for row in range(height):
            for col in range(width):
                idx = (row * width + col) * 3
                r, g, b = pixels[idx], pixels[idx+1], pixels[idx+2]
                color_hex = f"#{r:02x}{g:02x}{b:02x}"
                canvas.create_rectangle(x + col, y + row, x + col + 1, y + row + 1,
                                        outline=color_hex, fill=color_hex)
        ql.arch.regs.rax = 0

    elif syscall_num == 7417:  # xapi_ReadBufferAO (RGBA)
        handle = ql.arch.regs.rdi
        x = ql.arch.regs.rsi
        y = ql.arch.regs.rdx
        width = ql.arch.regs.r10
        height = ql.arch.regs.r8
        buffer_ptr = ql.arch.regs.r9

        win = windows.get(handle)
        if not win or not hasattr(win, 'canvas'):
            ql.arch.regs.rax = -1
            return

        win.update_idletasks()
        abs_x = win.winfo_rootx() + x
        abs_y = win.winfo_rooty() + y

        try:
            img = ImageGrab.grab(bbox=(abs_x, abs_y, abs_x + width, abs_y + height))
            img = img.convert('RGBA')
            pixels = img.tobytes()   # 每像素4字节 (R,G,B,A)
            ql.mem.write(buffer_ptr, pixels)
            ql.arch.regs.rax = 0
        except Exception as e:
            print(f"[xapi_ReadBufferAO] 错误: {e}")
            ql.arch.regs.rax = -1

    elif syscall_num == 7408:  # xapi_WriteBufferAO (RGBA)
        handle = ql.arch.regs.rdi
        x = ql.arch.regs.rsi
        y = ql.arch.regs.rdx
        width = ql.arch.regs.r10
        height = ql.arch.regs.r8
        buffer_ptr = ql.arch.regs.r9

        win = windows.get(handle)
        if not win or not hasattr(win, 'canvas'):
            ql.arch.regs.rax = -1
            return

        data_size = width * height * 4
        pixels = ql.mem.read(buffer_ptr, data_size)
        if len(pixels) != data_size:
            print(f"[xapi_WriteBufferAO] 读取内存失败")
            ql.arch.regs.rax = -1
            return

        canvas = win.canvas
        for row in range(height):
            for col in range(width):
                idx = (row * width + col) * 4
                r, g, b, a = pixels[idx], pixels[idx+1], pixels[idx+2], pixels[idx+3]
                # Alpha 混合暂不实现，直接使用 RGB 绘制
                color_hex = f"#{r:02x}{g:02x}{b:02x}"
                canvas.create_rectangle(x + col, y + row, x + col + 1, y + row + 1,
                                        outline=color_hex, fill=color_hex)
        ql.arch.regs.rax = 0

    elif syscall_num == 7438:  # xapi_RefreshPartWindow
        handle = ql.arch.regs.rdi

        win = windows.get(handle)
        if win:
            # Tkinter canvas 没有局部刷新 API，调用 update 强制重绘整个窗口
            win.update_idletasks()
        ql.arch.regs.rax = 0
    # ---------- 4.6 控件 ----------
    elif syscall_num == 7410:  # xapi_Button
        handle = ql.arch.regs.rdi
        crl_id = ql.arch.regs.rsi
        x = ql.arch.regs.rdx
        y = ql.arch.regs.r10
        text_ptr = ql.arch.regs.r8
        text = ql.mem.string(text_ptr) if text_ptr else ""
        win = windows.get(handle)
        if win:
            # 计算文本宽度
            font = tkfont.nametofont("TkDefaultFont")
            text_width = font.measure(text)
            btn_width = text_width + 22
            btn_height = 24
            # 创建普通按钮
            def callback(crl_id=crl_id, hdl=handle):
                # 将控件消息加入事件队列
                event_list.append([hdl, "button_click", crl_id])
            btn = tk.Button(win, text=text, command=callback)
            btn.place(x=x, y=y, width=btn_width, height=btn_height)
            win.buttons[crl_id] = btn
        ql.arch.regs.rax = 0

    elif syscall_num == 7411:  # xapi_EmButton (强调按钮)
        handle = ql.arch.regs.rdi
        crl_id = ql.arch.regs.rsi
        x = ql.arch.regs.rdx
        y = ql.arch.regs.r10
        text_ptr = ql.arch.regs.r8
        text = ql.mem.string(text_ptr) if text_ptr else ""
        win = windows.get(handle)
        if win:
            font = tkfont.nametofont("TkDefaultFont")
            text_width = font.measure(text)
            btn_width = text_width + 22
            btn_height = 24
            def callback(crl_id=crl_id, hdl=handle):
                event_list.append([hdl, "button_click", crl_id])
            btn = tk.Button(win, text=text, command=callback,
                            bg="#0078D7", fg="white", activebackground="#005A9E")
            btn.place(x=x, y=y, width=btn_width, height=btn_height)
            win.buttons[crl_id] = btn
        ql.arch.regs.rax = 0

    elif syscall_num == 7432:  # xapi_DeleteButton
        handle = ql.arch.regs.rdi
        crl_id = ql.arch.regs.rsi
        win = windows.get(handle)
        if win and crl_id in win.buttons:
            win.buttons[crl_id].destroy()
            del win.buttons[crl_id]
        ql.arch.regs.rax = 0

    elif syscall_num == 7436:  # xapi_RegisterRightButtonMenu
        handle = ql.arch.regs.rdi
        items_ptr = ql.arch.regs.rsi
        count = ql.arch.regs.rdx
        win = windows.get(handle)
        if win and items_ptr and count > 0:
            # 删除已有的右键菜单
            if win.right_menu:
                win.unbind("<Button-3>")
                win.right_menu.destroy()
            # 创建新菜单
            menu = tk.Menu(win, tearoff=0)
            for i in range(count):
                # 读取 RightMenuItem: CRLid(8) + text_ptr(8)
                item_addr = items_ptr + i * 16
                crl_id = struct.unpack("Q", ql.mem.read(item_addr, 8))[0]
                text_ptr = struct.unpack("Q", ql.mem.read(item_addr + 8, 8))[0]
                text = ql.mem.string(text_ptr) if text_ptr else ""
                print(str(crl_id) + text)
                def menu_callback(crl_id=crl_id, hdl=handle):
                    event_list.append([hdl, "button_click", crl_id])
                menu.add_command(label=text, command=menu_callback)
            # 绑定右键弹出
            def show_menu(event, menu=menu):
                menu.post(event.x_root, event.y_root)
            win.bind("<Button-3>", show_menu)
            win.right_menu = menu
        ql.arch.regs.rax = 0

    elif syscall_num == 7437:  # xapi_DeleteRightButtonMenu
        handle = ql.arch.regs.rdi
        win = windows.get(handle)
        if win and win.right_menu:
            win.unbind("<Button-3>")
            win.right_menu.destroy()
            win.right_menu = None
        ql.arch.regs.rax = 0

    # 其他未实现的系统调用保持原样（默认 rax=0）
    else:
        print("no:"+str(syscall_num))

    return
def create_handler(root):
    def on_global_event(event):
        if event.type == tk.EventType.KeyPress:
            event_list.append([root,"KeyPress",event])
        elif event.type == tk.EventType.Motion:
            event_list.append([root, "mouse_move", event])
        elif event.type == tk.EventType.ButtonPress:
            event_list.append([root, "mouse_button_prise", event])
        elif event.type == tk.EventType.MouseWheel:
            event_list.append([root, "mouse_Wheel", event])

    return on_global_event
def on_user_clothing():
    os._exit(0)

