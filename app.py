from tkinter import filedialog, messagebox, ttk
from gmssl import sm3
import tkinter as tk
import webbrowser
import datetime
import hashlib
import os


class HashComparerApp:
    def __init__(self, root=None):
        self.root = root
        self.result_text = None
        self.history_list = None

        self.root.title("OKMS 文件防伪工具(MD5/国密SM3/SHA1/SHA256)")
        self.set_window_center(880, 650)

        # 设置程序图标
        try:
            icon_path = os.path.join(os.path.dirname(__file__), "icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"加载图标失败: {e}")

        self.file1_path = tk.StringVar()
        self.file2_path = tk.StringVar()
        self.algorithm = tk.StringVar(value="MD5")
        self.save_dir = tk.StringVar()
        self.history = []

        self.create_widgets()

    def set_window_center(self, width, height):
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.resizable(False, False)

    def create_widgets(self):
        style = ttk.Style()
        style.configure("TButton", font=("微软雅黑", 10))
        style.configure("TLabel", font=("微软雅黑", 10))
        style.configure("TEntry", font=("微软雅黑", 10))

        frame = ttk.Frame(self.root)
        frame.pack(padx=20, pady=10, fill="x")

        ttk.Label(frame, text="文件1:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.file1_path, width=90).grid(row=0, column=1, pady=5)
        ttk.Button(frame, text="选择文件", command=self.select_file1).grid(row=0, column=2, padx=5)

        ttk.Label(frame, text="文件2:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.file2_path, width=90).grid(row=1, column=1, pady=5)
        ttk.Button(frame, text="选择文件", command=self.select_file2).grid(row=1, column=2, padx=5)

        ttk.Label(frame, text="算法:").grid(row=2, column=0, sticky="w", pady=5)
        algo_combo = ttk.Combobox(frame, textvariable=self.algorithm, values=["MD5", "SM3", "SHA1", "SHA256"],
                                  state="readonly", width=88)
        algo_combo.grid(row=2, column=1, pady=5, sticky="w")

        ttk.Label(frame, text="报告保存目录:").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.save_dir, width=90).grid(row=3, column=1, pady=5)
        ttk.Button(frame, text="选择目录", command=self.select_save_dir).grid(row=3, column=2, padx=5)

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="开始对比", command=self.compare_files).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="清空", command=self.clear_all).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="复制结果", command=self.copy_result).pack(side="left", padx=10)

        ttk.Label(self.root, text="对比结果:").pack(anchor="w", padx=20)
        self.result_text = tk.Text(self.root, height=10, width=105, font=("微软雅黑", 10))
        self.result_text.pack(padx=20, pady=5)

        ttk.Label(self.root, text="对比历史记录:").pack(anchor="w", padx=20)
        self.history_list = tk.Listbox(self.root, height=8, font=("微软雅黑", 10))
        self.history_list.pack(padx=20, pady=5, fill="both")
        self.history_list.bind("<Double-Button-1>", self.open_report)

        ttk.Label(self.root, text="2020-2025 12305.NET 版权所有", font=("微软雅黑", 8)).pack(
            side="bottom", pady=4)

    def select_file1(self):
        path = filedialog.askopenfilename()
        if path:
            self.file1_path.set(path)

    def select_file2(self):
        path = filedialog.askopenfilename()
        if path:
            self.file2_path.set(path)

    def select_save_dir(self):
        path = filedialog.askdirectory()
        if path:
            self.save_dir.set(path)

    def calculate_hash(self, filepath, algorithm):
        with open(filepath, "rb") as f:
            data = f.read()
        if algorithm == "MD5":
            return hashlib.md5(data).hexdigest()
        elif algorithm == "SM3":
            return sm3.sm3_hash(list(data))
        elif algorithm == "SHA1":
            return hashlib.sha1(data).hexdigest()
        elif algorithm == "SHA256":
            return hashlib.sha256(data).hexdigest()
        else:
            raise ValueError("不支持的算法")

    def compare_files(self):
        file1 = self.file1_path.get()
        file2 = self.file2_path.get()
        algo = self.algorithm.get()
        save_dir = self.save_dir.get()

        if not file1 or not file2 or not save_dir:
            messagebox.showerror("错误", "请完整选择文件和保存目录")
            return

        hash1 = self.calculate_hash(file1, algo)
        hash2 = self.calculate_hash(file2, algo)
        is_same = hash1 == hash2

        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename1 = os.path.basename(file1)
        filename2 = os.path.basename(file2)
        report_name = f"{filename1}_{filename2}_{algo}_{now}.txt"
        report_path = os.path.join(save_dir, report_name)

        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("文件对比报告\n")
            f.write("=" * 100 + "\n")
            f.write(f"对比时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"对比算法: {algo}\n")
            f.write(f"文件大小1: {os.path.getsize(file1)} bytes\n")
            f.write(f"文件大小2: {os.path.getsize(file2)} bytes\n")
            f.write(f"文件1: {file1}\n")
            f.write(f"文件2: {file2}\n")
            f.write(f"哈希1: {hash1}\n")
            f.write(f"哈希2: {hash2}\n")
            f.write(f"对比结果: {'一致' if is_same else '不一致'}\n")
            f.write("=" * 100 + "\n")

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"对比算法: {algo}\n")
        self.result_text.insert(tk.END, f"文件1哈希: {hash1}\n")
        self.result_text.insert(tk.END, f"文件2哈希: {hash2}\n")
        self.result_text.insert(tk.END, f"对比结果: {'一致' if is_same else '不一致'}\n")

        if is_same:
            self.result_text.tag_configure("same", foreground="green")
            self.result_text.insert(tk.END, "文件一致", "same")
        else:
            self.result_text.tag_configure("diff", foreground="red")
            self.result_text.insert(tk.END, "文件不一致", "diff")

        self.history.append(report_path)
        self.history_list.insert(tk.END, report_path)

    def clear_all(self):
        self.file1_path.set("")
        self.file2_path.set("")
        self.algorithm.set("MD5")
        self.result_text.delete(1.0, tk.END)

    def open_report(self, event):
        selection = self.history_list.curselection()
        if selection:
            path = self.history_list.get(selection[0])
            if os.path.exists(path):
                webbrowser.open(path)
            else:
                messagebox.showerror("错误", "报告文件不存在")

    def copy_result(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.result_text.get(1.0, tk.END))
        self.root.update()


if __name__ == "__main__":
    root = tk.Tk()
    app = HashComparerApp(root)
    root.mainloop()
