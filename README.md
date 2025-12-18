# 基于 SMP 协议的安全即时通讯系统 (SMP Protocol Chat System)

> **课程名称**：高级计算机网络  
> **项目类型**：课程大作业  
> **语言**：Python 3.9+  
> **GUI 框架**：Tkinter

## 📖 项目简介 (Introduction)

本项目设计并实现了一个基于 TCP 的自定义应用层协议 —— **SMP (Simple Message Protocol)**。基于该协议，构建了一套完整的 C/S 架构即时通讯系统。

系统摒弃了现成的 HTTP/WebSocket 框架，从底层 Socket 编程入手，解决了 TCP 粘包/拆包问题，实现了用户认证、私聊、群聊、好友管理以及支持断点续传思想的文件传输功能。

## ✨ 核心功能 (Features)

*   **自定义协议设计**：采用“二进制定长包头 (9 Bytes) + 变长 JSON 载荷”的混合协议格式，有效处理 TCP 字节流边界。
*   **安全认证**：使用 `PBKDF2_HMAC_SHA256` 算法加盐存储用户密码，保障用户信息安全。
*   **即时通讯**：
    *   👥 好友系统：添加好友、接受请求、好友列表持久化。
    *   💬 多模式聊天：支持点对点私聊 (Private Chat) 和多人群组广播 (Group Chat)。
    *   📜 历史记录：聊天记录存入 SQLite，支持离线消息漫游。
*   **文件传输**：
    *   📁 **分块传输**：将大文件切割为 8KB 数据块发送，避免阻塞主线程。
    *   🔒 **完整性校验**：传输前后进行 SHA256 哈希比对，确保文件未损坏。
*   **图形界面**：基于 Tkinter 开发的多窗口 GUI，操作友好。

## 📂 项目结构 (File Structure)

```text
smp_protocol/
├── server_enhanced.py   # [入口] 服务器端主程序，负责连接管理与消息路由
├── client_gui_V3.py     # [入口] 客户端 GUI 主程序
├── protocol.py          # [核心] SMP 协议编解码器 (解决粘包问题)
├── database.py          # [核心] SQLite 数据库管理 (用户、关系、日志)
├── file_transfer.py     # [核心] 文件分块处理与哈希校验工具
├── auth.py              # 安全认证模块 (密码哈希)
├── client_enhanced.py   # 客户端网络逻辑层 (处理 Socket IO)
├── smp_data_v4.db       # SQLite 数据库文件 (自动生成)
├── ssl_wrapper.py       # SSL/TLS 加密通信包装器 (可选)
├── requirement.txt      # 项目依赖库列表
└── server_files/        # 服务器端文件存储目录
```

## 🚀 快速开始 (Quick Start)

### 1. 环境准备

确保已安装 Python 3.8 或以上版本。

```bash
# 克隆项目 (如果已下载压缩包则跳过)
git clone https://github.com/yudonwansui-cmyk/smp_protocol.git
cd smp_protocol

# 安装依赖 (本项目主要依赖 Python 标准库，但建议检查)
pip install -r requirement.txt
```

### 2. 启动服务器

在终端中运行服务器脚本：

```bash
python server_enhanced.py
```
*控制台显示 `>>> 服务器 V5 已在 0.0.0.0:8899 启动 <<<` 即表示成功。*

### 3. 启动客户端

打开新的终端窗口（建议打开两个以测试聊天），运行客户端脚本：

```bash
python client_gui_V3.py
```

### 4. 操作指引

1.  **注册**：点击 "Don't have an account? Register"，输入用户名和密码注册。
2.  **登录**：使用注册的账号登录。
3.  **加好友**：
    *   在左上角输入框输入另一个用户的 ID（如 `1002`），点击 "Add"。
    *   另一个客户端会收到弹窗，点击 "Yes" 接受。
4.  **聊天与文件**：点击左侧好友列表，即可开始聊天或发送文件。

## 🛠️ 协议规范 (Protocol Spec)

本项目定义的 SMP 协议包结构如下（大端序）：

| 字段 (Field) | 长度 (Length) | 类型 | 说明 |
| :--- | :--- | :--- | :--- |
| **Msg Type** | 1 Byte | `uint8` | 消息类型 (如 0x01=Login, 0x0F=FileChunk) |
| **Msg ID** | 4 Bytes | `uint32` | 消息序列号，用于请求/响应匹配 |
| **Body Len** | 4 Bytes | `uint32` | 后续 JSON 载荷的长度 |
| **Payload** | Variable | `bytes` | UTF-8 编码的 JSON 数据 |

## 📝 待办 / 改进计划 (ToDo)

- [ ] 引入 SSL/TLS 证书实现全链路加密 (已包含 `ssl_wrapper.py`，待完全集成)。
- [ ] 增加 WebSocket 网关支持 Web 端访问。
- [ ] 优化大文件传输的进度条显示。

## 📜 许可证 (License)

本项目仅供学习交流使用。

Copyright © 2025 yudonwansui-cmyk
