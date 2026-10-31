# Telegram Clean macOS

全自动构建 macOS 原生版 Telegram（Swift）去广告纯净客户端：

- **彻底去除频道赞助商广告**（`AdMessagesHistoryContext`）
- **彻底去除全局搜索推广广告**（`contacts.getSponsoredPeers` / `_internal_searchAdPeers`）
- **解除频道/群组防复制、防转发与防保存限制**（`isCopyProtected` / `isCopyProtectionEnabled`）
- **移除设置页全部付费与会员推销菜单**（Telegram Premium、Telegram Stars、TON/Balance、Telegram Business、Send a Gift、Wallet、顶部表情状态与个人主页颜色推销栏）
- **完美支持 Apple Silicon (`arm64`) 与 Intel (`x86_64`) 双架构**

## 下载与安装

1. 前往本仓库右侧的 **[Releases](../../releases)** 页面，下载最新的 `Telegram-Clean-macOS.dmg`。
2. 双击打开 `Telegram-Clean-macOS.dmg`，将 `Telegram.app` 拖入 `Applications`（若已有官方版，直接选择“替换”，原有登录状态与聊天记录完全保留）。
3. 首次打开若提示“无法验证开发者 / 已损坏”，在终端执行以下命令即可永久正常使用：

```bash
sudo xattr -rd com.apple.quarantine /Applications/Telegram.app
```

## 手动触发云端更新

当 Telegram 官方发布新版本时：
1. 点击仓库顶部的 **Actions** -> **Auto Build Clean Telegram macOS**。
2. 点击右侧 **Run workflow** 按钮，约 3 分钟即可自动生成最新版本的纯净安装包并发布到 Releases。
