# Hysteria2 一键部署脚本

这是一个专为跨境电商店铺设计的 Hysteria2 协议节点一键部署脚本，旨在提升网络稳定性、抗检测能力、伪装能力和连接持久性。

## 功能特点

- ✅ 一键部署 Hysteria2 协议节点
- ✅ 使用自签名证书（不使用域名）
- ✅ 支持端口跳跃（Port Hopping），使用非标准、不连续的 UDP 端口
- ✅ 使用 Salamander 混淆技术，增强流量伪装
- ✅ 部署 Nginx 作为反向代理，监听 443 端口，伪装为正常 HTTPS 流量
- ✅ 自动生成分享链接，可直接用于软路由（如 OpenWRT 的 PassWall）
- ✅ 自签名证书有效期为 1 年（365 天）
- ✅ 优化系统参数（BBR、MTU、超时设置等），提高连接稳定性
- ✅ 提供管理菜单，便于日常维护和管理
- ✅ 断联问题解决方案：服务状态监控和自动重启功能

## 系统要求

- 支持 CentOS 7+/Debian 10+/Ubuntu 18+
- 需要 root 权限
- 支持 x86_64/amd64 和 ARM64 架构

## 一键部署命令

### Debian/Ubuntu 系统:

```bash
apt update && apt install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/Fanjuanjuan7/hysteria2-deploy/main/hysteria2_deploy.sh)
```

### CentOS/RHEL 系统:

```bash
yum install -y curl && bash <(curl -fsSL https://raw.githubusercontent.com/Fanjuanjuan7/hysteria2-deploy/main/hysteria2_deploy.sh)
```

## 手动部署方法

### 1. 克隆项目到本地

```bash
git clone https://github.com/Fanjuanjuan7/hysteria2-deploy.git
cd hysteria2-deploy
```

### 2. 给脚本执行权限并运行

```bash
chmod +x hysteria2_deploy.sh
sudo ./hysteria2_deploy.sh
```

## 安装完成后

脚本会自动完成以下步骤：
- 安装所有必要依赖
- 优化系统参数和启用 BBR
- 生成有效期为 365 天的自签名证书
- 安装并配置 Hysteria2
- 设置 Nginx 反向代理
- 启动 Hysteria2 服务
- 设置服务监控和自动恢复机制
- 生成分享链接
- 创建管理菜单

## 使用管理菜单

安装完成后，使用以下命令进入管理菜单：

```bash
fff
```

管理菜单提供以下功能：
1. 重新安装 Hysteria2
2. 查看当前 Hysteria2 状态
3. 显示分享链接
4. 查看当前配置信息
5. 卸载 Hysteria2
0. 退出菜单

## 客户端配置

安装完成后，脚本会生成一个分享链接，可以直接在支持 Hysteria2 协议的客户端中使用：

- Clash Meta
- PassWall (OpenWRT)
- SagerNet
- Shadowrocket
- 其他支持 Hysteria2 协议的客户端

## 断联问题解决方案

本脚本包含多项优化，专门解决 Hysteria2 常见的断联问题：

1. **网络参数优化**
   - TCP 和 UDP 参数调优
   - 更积极的 TCP Keepalive 设置 (600秒间隔，15秒检测频率)
   - 更大的接收/发送窗口
   - BBR 拥塞控制算法

2. **Hysteria2 配置优化**
   - 更长的 UDP 空闲超时时间 (60秒)
   - 更短的认证超时时间 (3秒)
   - 优化的窗口大小
   - 更高的最大客户端连接数

3. **自动监控和恢复**
   - 每5分钟检查一次服务状态
   - 自动检测并重启异常服务
   - 监控网络连接并尝试恢复
   - 系统日志记录所有异常和恢复操作

## 安全与性能优化

本脚本包含多项安全与性能优化：

- 使用 Salamander 混淆技术，有效抵抗 DPI 检测
- 启用 BBR 拥塞控制算法，提高网络吞吐量
- 优化 TCP/UDP 参数，提高连接稳定性和响应速度
- 采用端口跳跃技术，增强抗封锁能力
- 使用 Nginx 伪装流量，降低被识别风险

## 部署到 GitHub

### 1. 创建 GitHub 仓库

1. 登录到 GitHub
2. 点击右上角的 "+" 按钮，选择 "New repository"
3. 填写仓库名称，如 `hysteria2-deploy`
4. 添加描述（可选）
5. 设置为公开仓库
6. 点击 "Create repository"

### 2. 初始化本地仓库并推送

```bash
# 初始化仓库
git init

# 添加文件
git add hysteria2_deploy.sh README.md

# 提交更改
git commit -m "Initial commit: Hysteria2 deploy script"

# 添加远程仓库
git remote add origin https://github.com/用户名/hysteria2-deploy.git

# 推送到 GitHub
git push -u origin main
```

### 3. 更新一键部署命令

将 README.md 中的一键部署命令中的 "用户名" 替换为您的 GitHub 用户名。

## 故障排查

如果遇到问题，请尝试以下步骤：

1. 检查服务状态：`systemctl status hysteria2`
2. 查看日志：`journalctl -u hysteria2 -n 50`
3. 检查监控日志：`cat /var/log/hysteria2_watchdog.log`
4. 检查端口是否开放：`netstat -antup | grep hysteria`
5. 重新启动服务：`systemctl restart hysteria2`
6. 如仍有问题，可使用 `fff` 命令进入管理菜单，选择重新安装或卸载选项

## 注意事项

- 本脚本会在服务器上开放多个 UDP 端口，请确保防火墙设置允许这些端口通信
- 自签名证书在客户端需要设置 `insecure=1` 选项（分享链接中已包含）
- 如需在多台服务器上部署，建议每台使用不同的端口配置 
