# XJ380 跨平台兼容层 (XSWL)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/yaoyaomenke/XJ380-SubSystems-on-Windows-and-Linux-XSWL-)

**XJ380 操作系统程序的跨平台运行环境** - 让 XJ380 平台的应用程序能够在 Windows、Linux 和 macOS 上原生运行。

## ✨ 项目简介

XJ380-Wine（代号 XSWL）是一个基于 [Qiling 框架](https://github.com/qilingframework/qiling) 构建的兼容层，专门用于在主流操作系统上运行 XJ380 操作系统的可执行文件。它通过模拟 XJ380 特有的系统调用，将图形界面、文件操作、网络功能等映射到宿主机的实际 API 上。

### 项目名称含义
- **XSWL** = XJ380 SubSystems on Windows and Linux
- 致敬 Wine (Wine Is Not an Emulator)，采用类似的设计理念

## 🎯 主要特性

### ✅ 已实现功能

#### 1. 图形界面系统 (GUI)
- 窗口创建、关闭、标题设置
- 绘图原语：点、线、矩形、圆形、文本
- 图片支持：BMP、PNG、SVG 格式
- 控件支持：按钮、右键菜单
- 键盘、鼠标事件处理

#### 2. 文件系统操作
- 文件读写（支持偏移）
- 文件创建、删除、重命名
- 目录创建和递归删除
- 目录遍历和搜索

#### 3. 网络功能
- DNS 域名解析（IPv4/IPv6）
- 网络状态信息获取
- poll 系统调用支持

#### 4. 系统信息获取
- 获取系统版本
- 获取当前时间（支持两种格式）
- 获取 CPU 型号
- 获取内存大小
- 获取当前用户信息

#### 5. 内存管理
- 动态内存分配/释放
- 内存映射

#### 6. 其他功能
- 控制台输入/输出
- 程序休眠
- 打开外部程序/文件
- 简单的消息对话框

### ❌ 暂未实现
- 进程创建 (xapi_Fork, xapi_Execve)
- 部分高级网络功能

## 🚀 快速开始

### 环境要求

- **Python 3.8 或更高版本**
- 支持的操作系统：Windows 10+ / Linux / macOS

### 安装步骤

#### 1. 克隆仓库

```bash
git clone https://github.com/yaoyaomenke/XJ380-SubSystems-on-Windows-and-Linux-XSWL-.git
cd XJ380-SubSystems-on-Windows-and-Linux-XSWL-
