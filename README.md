# OKMS 文件防伪工具~~~~

### 构建打包 `.exe` 的方法：

需要在命令行执行：

```bash
pip install pyinstaller
```

然后用下面这个命令打包：

```bash
pyinstaller -F -w -i icon.ico app.py
```

参数说明：

- `-F` ：打包成一个单一 `.exe` 文件
- `-w` ：不显示黑框（窗口程序）~~~~
- `-i` ：指定icon图标
- `app.py`：你的 `.py` 文件名

打包后会在 `dist` 文件夹里生成你的 `exe`，兼容 Windows 10/11，系统通吃！🔥