# -*- coding: utf-8 -*-
# TOTP 剪贴板助手 (Win10)
# 特性：
# - 托盘图标（双击显示/隐藏）、Toast 提示
# - 监测剪贴板中的 TOTP 秘钥 → 生成动态码 → 写回剪贴板
# - 仅识别纯 Base32（无 URL）或 otpauth://totp/... 链接
# - 显示当前秘钥（默认展示，可隐藏）
# - 倒计时结束后自动刷新最近秘钥的验证码并写回剪贴板
# - 全局热键：暂停 / 启用（可在界面调整并保存）
#
# 依赖: pyperclip pystray pillow win10toast keyboard
# 运行: python totp_clip_gui.py
# 打包: pyinstaller --onefile --windowed --name TOTP剪贴板助手 totp_clip_gui.py

import os
import json
import time
import re
import base64
import hmac
import hashlib
import struct
import threading
from urllib.parse import urlparse, parse_qs, unquote

import pyperclip

# GUI / 托盘 / 提示
import tkinter as tk
from tkinter import ttk, messagebox

import pystray
from pystray import MenuItem as Item
from PIL import Image, ImageDraw, ImageFont

try:
    from win10toast import ToastNotifier
    toaster = ToastNotifier()
except Exception:
    toaster = None

# 全局热键库（可选）
try:
    import keyboard
    HOTKEYS_AVAILABLE = True
except Exception:
    HOTKEYS_AVAILABLE = False

# ---------- 配置持久化 ----------
def get_config_path():
    base = os.environ.get('APPDATA', os.path.expanduser('~'))
    cfg_dir = os.path.join(base, 'TOTPClipHelper')
    os.makedirs(cfg_dir, exist_ok=True)
    return os.path.join(cfg_dir, 'config.json')

DEFAULT_CONFIG = {
    "hotkey_pause": "ctrl+alt+9",
    "hotkey_resume": "ctrl+alt+0"
}

def load_config():
    path = get_config_path()
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return {**DEFAULT_CONFIG, **data}
        except Exception:
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()

def save_config(cfg: dict):
    path = get_config_path()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

# ---------- TOTP ----------
BASE32_MIN = 16
BASE32_MAX = 64
POLL_INTERVAL = 0.30  # 剪贴板轮询间隔（秒）

# 允许 otpauth 链接
OTPAUTH_RE = re.compile(r"otpauth://totp/[^?\s]+?\?[^\s]+", re.IGNORECASE)

# URL（除 otpauth://）检测：出现任何 scheme:// 或 www. 即视为含链接
URL_RE = re.compile(r'(?i)\b(?:[a-z][a-z0-9+\-.]*://|www\.)')

# 严格 Base32 全匹配（仅裸秘钥使用）
FULL_BASE32_RE = re.compile(r'^[A-Z2-7]{%d,%d}$' % (BASE32_MIN, BASE32_MAX))

def b32_pad(s: str) -> str:
    s = s.strip().replace(" ", "").upper()
    missing = (-len(s)) % 8
    if missing:
        s += "=" * missing
    return s

def hotp(key: bytes, counter: int, digits: int = 6, algo: str = "SHA1") -> str:
    algo = algo.upper()
    if algo == "SHA1":
        digestmod = hashlib.sha1
    elif algo == "SHA256":
        digestmod = hashlib.sha256
    elif algo == "SHA512":
        digestmod = hashlib.sha512
    else:
        digestmod = hashlib.sha1
    c = struct.pack(">Q", counter)
    h = hmac.new(key, c, digestmod).digest()
    o = h[-1] & 0x0F
    code_int = ((h[o] & 0x7f) << 24) | ((h[o+1] & 0xff) << 16) | ((h[o+2] & 0xff) << 8) | (h[o+3] & 0xff)
    return str(code_int % (10 ** digits)).zfill(digits)

def totp(secret_b32: str, digits: int = 6, period: int = 30, algo: str = "SHA1") -> str:
    key = base64.b32decode(b32_pad(secret_b32), casefold=True)
    counter = int(time.time()) // period
    return hotp(key, counter, digits=digits, algo=algo)

def parse_otpauth(otpauth_url: str):
    """
    解析 otpauth://totp 链接
    返回: (secret, digits, period, algo, label, issuer)
    label/issuer 供显示（本版本默认不展示 label/issuer）
    """
    try:
        u = urlparse(otpauth_url)
        if u.scheme.lower() != "otpauth":
            return None
        qs = parse_qs(u.query)
        secret = (qs.get("secret", [""])[0] or "").strip()
        if not secret:
            return None
        digits = int(qs.get("digits", ["6"])[0])
        period = int(qs.get("period", ["30"])[0])
        algo = (qs.get("algorithm", ["SHA1"])[0] or "SHA1").upper()

        raw_label = u.path.split("/", 2)[-1] if "/" in u.path else u.path
        label = unquote(raw_label) if raw_label else None
        issuer = qs.get("issuer", [None])[0]
        if issuer:
            issuer = unquote(issuer)
        if not issuer and label and ":" in label:
            issuer = label.split(":", 1)[0].strip()
        return secret, digits, period, algo, label, issuer
    except Exception:
        return None

def extract_totp_params(text: str):
    """
    返回: (secret, digits, period, algo, label, issuer) 或 None
    逻辑：
      1) 优先识别 otpauth://totp/...
      2) 若文本包含 URL（http/https/任意 scheme:// 或 www.），则不做裸秘钥识别
      3) 否则仅当“去空白后”完全是 Base32（A-Z2-7，16~64）才当作裸秘钥
    """
    m = OTPAUTH_RE.search(text)
    if m:
        parsed = parse_otpauth(m.group(0))
        if parsed:
            return parsed

    stripped = text.strip()
    if URL_RE.search(stripped) and not stripped.lower().startswith("otpauth://"):
        return None

    cleaned = re.sub(r'\s+', '', stripped).upper()
    if FULL_BASE32_RE.fullmatch(cleaned):
        return (cleaned, 6, 30, "SHA1", None, None)

    return None

def looks_like_code(text: str) -> bool:
    return bool(re.fullmatch(r"\d{6,8}", text.strip()))

# ---------- Pillow 文本测量兼容（Pillow 10+ 无 textsize） ----------
def _measure_text(draw: ImageDraw.ImageDraw, text: str, font=None):
    if hasattr(draw, "textbbox"):
        bbox = draw.textbbox((0, 0), text, font=font)
        return (bbox[2] - bbox[0], bbox[3] - bbox[1])
    if hasattr(draw, "textsize"):
        return draw.textsize(text, font=font)
    if hasattr(font, "getsize"):
        return font.getsize(text)
    return (len(text) * 6, 10)

# ---------- 托盘图标 ----------
def make_icon(size=64):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((2, 2, size - 2, size - 2), fill=(28, 122, 255, 230))
    try:
        fnt = ImageFont.load_default()
    except Exception:
        fnt = None
    text = "TOTP"
    tw, th = _measure_text(d, text, fnt)
    d.text(((size - tw) / 2, (size - th) / 2), text, fill="white", font=fnt)
    return img

# ---------- 监控线程 ----------
class Watcher(threading.Thread):
    def __init__(self, app):
        super().__init__(daemon=True)
        self.app = app
        self.stop_event = threading.Event()
        self.last_seen = None
        self.last_emitted = None

    def stop(self):
        self.stop_event.set()

    def run(self):
        while not self.stop_event.is_set():
            try:
                current = pyperclip.paste()
            except Exception:
                time.sleep(POLL_INTERVAL)
                continue

            if current != self.last_seen:
                self.last_seen = current
                txt = (current or "").strip()

                # 跳过我们主动写入的数字（来自监测或自动刷新）
                if looks_like_code(txt) and (txt == (self.last_emitted or "") or txt == (self.app.last_auto_code or "")):
                    time.sleep(POLL_INTERVAL)
                    continue

                if not self.app.is_paused.get():
                    params = extract_totp_params(txt)
                    if params:
                        secret, digits, period, algo, label, issuer = params
                        try:
                            code = totp(secret, digits=digits, period=period, algo=algo)
                            pyperclip.copy(code)
                            self.last_emitted = code
                            # 更新 UI（参数 + 代码）
                            self.app.update_secret_params(secret, digits, period, algo)
                            self.app.update_code_ui(code, period, algo)
                            self.app.toast(f"已复制动态码：{code}（{period}s）")
                        except Exception as e:
                            self.app.set_status(f"生成失败：{e}")
                    else:
                        self.app.set_status("未识别到 2FA 秘钥，等待中…")
                else:
                    self.app.set_status("已暂停监测")

            time.sleep(POLL_INTERVAL)

# ---------- 主应用 ----------
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("2FA - 剪贴板助手         By:江屿")
        self.root.geometry("460x430")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close_window)

        # 状态
        self.is_paused = tk.BooleanVar(value=False)
        self.code_var = tk.StringVar(value="— — — — — —")
        self.status_var = tk.StringVar(value="等待复制秘钥…")
        self.countdown_var = tk.StringVar(value="")
        self.reveal_secret = tk.BooleanVar(value=True)  # 默认直接显示秘钥

        # 最近一次秘钥参数（用于自动刷新）
        self.last_secret = None
        self.last_digits = 6
        self.last_period = 30
        self.last_algo = "SHA1"
        self.last_gen_ts = 0
        self.last_counter = None
        self.last_auto_code = None  # 记录自动刷新写入的验证码（供 Watcher 跳过）

        # 载入配置（热键）
        self.config = load_config()

        # ----- UI -----
        frm = ttk.Frame(root, padding=12)
        frm.pack(fill="both", expand=True)

        # 当前动态码
        ttk.Label(frm, text="当前动态码：", font=("Segoe UI", 10)).pack(anchor="w")
        self.lbl_code = ttk.Label(frm, textvariable=self.code_var, font=("Consolas", 26, "bold"))
        self.lbl_code.pack(anchor="center", pady=4)

        # 倒计时 + 算法
        self.lbl_count = ttk.Label(frm, textvariable=self.countdown_var, font=("Segoe UI", 9))
        self.lbl_count.pack(anchor="center")

        sep1 = ttk.Separator(frm); sep1.pack(fill="x", pady=6)
        ttk.Label(frm, text="当前秘钥信息：", font=("Segoe UI", 10)).pack(anchor="w")

        info_grid = ttk.Frame(frm)
        info_grid.pack(fill="x", pady=2)

        ttk.Label(info_grid, text="算法/位数/周期：").grid(row=0, column=0, sticky="w", pady=(2,0))
        self.param_label = ttk.Label(info_grid, text="—")
        self.param_label.grid(row=0, column=1, sticky="w", pady=(2,0))

        ttk.Label(info_grid, text="秘钥：").grid(row=1, column=0, sticky="w", pady=(2,0))
        self.secret_label = ttk.Label(info_grid, text="—", font=("Consolas", 9))
        self.secret_label.grid(row=1, column=1, sticky="w", pady=(2,0))

        reveal_chk = ttk.Checkbutton(frm, text="显示秘钥", variable=self.reveal_secret, command=self.refresh_secret_display)
        reveal_chk.pack(anchor="w", pady=(2,0))

        sep2 = ttk.Separator(frm); sep2.pack(fill="x", pady=6)

        # 热键设置区
        hk_frame = ttk.LabelFrame(frm, text="全局快捷键（需要 keyboard 库）")
        hk_frame.pack(fill="x", pady=4)

        ttk.Label(hk_frame, text="暂停监测：").grid(row=0, column=0, sticky="e", padx=4, pady=2)
        self.hk_pause_var = tk.StringVar(value=self.config.get("hotkey_pause", DEFAULT_CONFIG["hotkey_pause"]))
        ttk.Entry(hk_frame, textvariable=self.hk_pause_var, width=20).grid(row=0, column=1, sticky="w", pady=2)

        ttk.Label(hk_frame, text="启用监测：").grid(row=0, column=2, sticky="e", padx=(12,4), pady=2)
        self.hk_resume_var = tk.StringVar(value=self.config.get("hotkey_resume", DEFAULT_CONFIG["hotkey_resume"]))
        ttk.Entry(hk_frame, textvariable=self.hk_resume_var, width=20).grid(row=0, column=3, sticky="w", pady=2)

        self.hk_status_var = tk.StringVar(value="热键状态：可用" if HOTKEYS_AVAILABLE else "热键状态：不可用（未安装/权限不足）")
        ttk.Label(hk_frame, textvariable=self.hk_status_var).grid(row=1, column=0, columnspan=4, sticky="w", padx=4, pady=(2,4))

        hk_btns = ttk.Frame(hk_frame)
        hk_btns.grid(row=2, column=0, columnspan=4, sticky="w", pady=(0,4))
        ttk.Button(hk_btns, text="应用", command=self.apply_hotkeys).grid(row=0, column=0, padx=4)
        ttk.Button(hk_btns, text="重置默认", command=self.reset_hotkeys_default).grid(row=0, column=1, padx=4)

        # 状态行
        self.lbl_status = ttk.Label(frm, textvariable=self.status_var, font=("Segoe UI", 9))
        self.lbl_status.pack(anchor="w", pady=(6,0))

        # 按钮
        btns = ttk.Frame(frm)
        btns.pack(anchor="center", pady=6)
        self.btn_pause = ttk.Button(btns, text="暂停监测", command=self.toggle_pause)
        self.btn_pause.grid(row=0, column=0, padx=6)
        ttk.Button(btns, text="最小化到托盘", command=self.hide_to_tray).grid(row=0, column=1, padx=6)
        ttk.Button(btns, text="退出", command=self.quit_all).grid(row=0, column=2, padx=6)

        # 托盘（默认项支持“双击托盘”）
        self.icon_image = make_icon(64)
        self.tray_icon = pystray.Icon(
            "2FA 剪贴板助手",
            self.icon_image,
            "2FA 剪贴板助手",
            menu=pystray.Menu(
                Item("显示/隐藏窗口", self.menu_toggle_show, default=True),
                Item("暂停/恢复监测", self.menu_toggle_pause),
                Item("退出", self.menu_exit),
            ),
        )
        self.tray_started = False
        self.tray_icon.run_detached(lambda i: setattr(i, "visible", True))
        self.tray_started = True

        # 定时器：倒计时 + 周期切换自动刷新
        self.tick()
        # 监控线程
        self.watcher = Watcher(self)
        self.watcher.start()
        # 注册热键
        self.apply_hotkeys(initial=True)

    # ---- 热键注册 ----
    def apply_hotkeys(self, initial=False):
        if not HOTKEYS_AVAILABLE:
            if not initial:
                messagebox.showwarning("提示", "keyboard 库不可用，无法注册全局热键。\n请执行：pip install keyboard（并可能需要以管理员权限运行）")
            return
        # 移除旧热键
        try:
            keyboard.unhook_all_hotkeys()
        except Exception:
            pass

        pause = (self.hk_pause_var.get() or "").strip()
        resume = (self.hk_resume_var.get() or "").strip()

        ok = True
        try:
            if pause:
                keyboard.add_hotkey(pause, lambda: self.root.after(0, self.set_paused, True))
            if resume:
                keyboard.add_hotkey(resume, lambda: self.root.after(0, self.set_paused, False))
        except Exception as e:
            ok = False
            self.hk_status_var.set(f"热键状态：注册失败（{e}）")

        if ok:
            self.hk_status_var.set(f"热键状态：已注册（暂停: {pause or '无'} | 启用: {resume or '无'}）")
            # 保存配置
            self.config["hotkey_pause"] = pause
            self.config["hotkey_resume"] = resume
            save_config(self.config)

    def reset_hotkeys_default(self):
        self.hk_pause_var.set(DEFAULT_CONFIG["hotkey_pause"])
        self.hk_resume_var.set(DEFAULT_CONFIG["hotkey_resume"])
        self.apply_hotkeys()

    def set_paused(self, flag: bool):
        self.is_paused.set(flag)
        if flag:
            self.btn_pause.config(text="恢复监测")
            self.set_status("已暂停监测（来自热键）")
        else:
            self.btn_pause.config(text="暂停监测")
            self.set_status("等待复制秘钥…（来自热键）")

    # ---- 业务：更新参数 & UI ----
    def update_secret_params(self, secret, digits, period, algo):
        def _apply():
            self.last_secret = secret
            self.last_digits = digits
            self.last_period = period
            self.last_algo = algo
            self.last_counter = int(time.time()) // period
            self.refresh_secret_display()
            self.param_label.config(text=f"{algo} / {digits} / {period}s")
        self.root.after(0, _apply)

    def refresh_secret_display(self):
        if not self.last_secret:
            self.secret_label.config(text="—")
            return
        s = self.last_secret
        if self.reveal_secret.get():
            shown = s
        else:
            if len(s) <= 8:
                shown = s
            else:
                shown = f"{s[:4]}…{s[-4:]}  (len={len(s)})"
        self.secret_label.config(text=shown)

    def update_code_ui(self, code, period, algo):
        def _apply():
            self.code_var.set(code)
            self.last_period = period
            self.last_algo = algo
            self.last_gen_ts = int(time.time() // period) * period
            self.status_var.set(f"已写入剪贴板（algo={algo}, period={period}s）")
        self.root.after(0, _apply)

    def set_status(self, text):
        self.root.after(0, lambda: self.status_var.set(text))

    def toast(self, msg):
        if toaster:
            try:
                toaster.show_toast("2FA 剪贴板助手", msg, duration=3, threaded=True)
            except Exception:
                pass

    # ---- 定时心跳：更新倒计时 + 周期切换时自动刷新 ----
    def tick(self):
        if self.last_gen_ts and self.last_period:
            now = int(time.time())
            left = self.last_period - ((now - self.last_gen_ts) % self.last_period)
            self.countdown_var.set(f"剩余 {left:02d}s  |  算法 {self.last_algo}")
            if self.last_secret:
                now_counter = now // self.last_period
                if self.last_counter is not None and now_counter != self.last_counter:
                    try:
                        code = totp(self.last_secret, digits=self.last_digits, period=self.last_period, algo=self.last_algo)
                        pyperclip.copy(code)
                        # 记录自动写入，避免监控线程误触发
                        self.last_auto_code = code
                        self.last_counter = now_counter
                        self.last_gen_ts = (now_counter) * self.last_period
                        self.code_var.set(code)
                        self.status_var.set(f"已自动刷新并写入剪贴板（{self.last_period}s）")
                        self.toast(f"已自动刷新：{code}")
                    except Exception as e:
                        self.status_var.set(f"自动刷新失败：{e}")
        else:
            self.countdown_var.set("")
        self.root.after(250, self.tick)

    # ---- 托盘/窗口 ----
    def ensure_tray(self):
        if not getattr(self, "tray_started", False) or not self.tray_icon.visible:
            try:
                self.tray_icon.run_detached(lambda i: setattr(i, "visible", True))
                self.tray_started = True
            except Exception:
                pass

    def hide_to_tray(self):
        self.ensure_tray()
        self.root.withdraw()
        self.toast("已最小化到托盘")

    def show_window(self):
        self.root.deiconify()
        self.root.after(10, self.root.lift)

    def toggle_show(self):
        if self.root.state() == "withdrawn":
            self.show_window()
        else:
            self.hide_to_tray()

    def on_close_window(self):
        self.hide_to_tray()

    def quit_all(self):
        try:
            if hasattr(self, "watcher") and self.watcher:
                self.watcher.stop()
        except Exception:
            pass
        try:
            if hasattr(self, "tray_icon") and self.tray_icon:
                self.tray_icon.stop()
        except Exception:
            pass
        if HOTKEYS_AVAILABLE:
            try:
                keyboard.unhook_all_hotkeys()
            except Exception:
                pass
        self.root.destroy()

    # ---- 托盘菜单回调（切回主线程）----
    def menu_toggle_show(self, icon, item):
        self.root.after(0, self.toggle_show)

    def menu_toggle_pause(self, icon, item):
        self.root.after(0, self.toggle_pause)

    def menu_exit(self, icon, item):
        self.root.after(0, self.quit_all)

    # ---- 暂停/恢复（按钮/托盘/热键共用）----
    def toggle_pause(self):
        self.is_paused.set(not self.is_paused.get())
        if self.is_paused.get():
            self.btn_pause.config(text="恢复监测")
            self.set_status("已暂停监测")
        else:
            self.btn_pause.config(text="暂停监测")
            self.set_status("等待复制秘钥…")

def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
