# 这玩意由CHATGPT生成，包含以下文档均为GPT生成！

# Windows 下将 Python 脚本打包成 EXE（TOTP 剪贴板助手）

## 一次性步骤

### 1) 检查 Python & pip
```bat
py -V
py -m pip -V
```

### 2)（推荐）创建并激活虚拟环境
```bat
py -3 -m venv .venv
.\.venv\Scripts\activate
```

### 3) 安装依赖
```bat
pip install -U pip
pip install pyinstaller pyperclip pystray pillow win10toast keyboard
```

### 4) 本地运行验证
```bat
python totp_clip_gui.py
```

---

## 打包成 EXE

### 调试版（带控制台，便于查看日志）
```bat
pyinstaller --onefile totp_clip_gui.py
```

### 正式版（无黑框窗口）
```bat
pyinstaller --onefile --windowed --name "TOTP剪贴板助手" totp_clip_gui.py
```

### 可选：自定义图标（准备 `totp.ico`）
```bat
pyinstaller --onefile --windowed --icon totp.ico --name "TOTP剪贴板助手" totp_clip_gui.py
```

**打包完成后文件位置：**  
`dist\TOTP剪贴板助手.exe`

---

## 开机自启（可选）
1. 按 `Win + R`  
2. 输入 `shell:startup` 并回车  
3. 将 `TOTP剪贴板助手.exe` 的**快捷方式**放入打开的启动文件夹即可
