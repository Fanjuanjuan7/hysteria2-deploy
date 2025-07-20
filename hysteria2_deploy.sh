#!/bin/bash

# Hysteria2 一键部署简化版脚本 - 修复了所有语法问题

# 检查root权限
if [[ $EUID -ne 0 ]]; then
  echo "错误: 必须使用root用户运行此脚本"
  exit 1
fi

# 颜色设置
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

echo -e "${GREEN}======================================${PLAIN}"
echo -e "${GREEN}  Hysteria2 一键部署脚本 - 简化版   ${PLAIN}"
echo -e "${GREEN}======================================${PLAIN}"

# 安装依赖
echo -e "${YELLOW}正在安装依赖...${PLAIN}"
if [ -f /etc/debian_version ]; then
  # Debian/Ubuntu
  apt update -y
  apt install -y curl wget unzip tar openssl nginx socat jq xxd
elif [ -f /etc/redhat-release ]; then
  # CentOS/RHEL
  yum update -y
  yum install -y curl wget unzip tar openssl nginx socat jq
else
  echo -e "${RED}不支持的操作系统${PLAIN}"
  exit 1
fi

# 创建目录
echo -e "${YELLOW}创建必要目录...${PLAIN}"
mkdir -p /etc/hysteria2/cert
mkdir -p /usr/local/bin/hysteria2
mkdir -p /var/www/html

# 下载Hysteria2
echo -e "${YELLOW}下载Hysteria2...${PLAIN}"
latest=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
if [ -z "$latest" ]; then
  latest="v1.3.4" # 默认版本
fi
echo -e "${GREEN}最新版本: $latest${PLAIN}"

# 检测系统架构
arch=$(uname -m)
if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
  ARCH="amd64"
elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
  ARCH="arm64"
else
  echo -e "${RED}不支持的系统架构: ${arch}${PLAIN}"
  exit 1
fi

# 下载对应架构的二进制文件
wget -O /usr/local/bin/hysteria2/hysteria "https://github.com/apernet/hysteria/releases/download/${latest}/hysteria-linux-${ARCH}"
if [ $? -ne 0 ]; then
  echo -e "${RED}下载失败，请检查网络或手动下载${PLAIN}"
  exit 1
fi
chmod +x /usr/local/bin/hysteria2/hysteria

# 测试是否可执行
if ! /usr/local/bin/hysteria2/hysteria version; then
  echo -e "${RED}Hysteria2 安装失败${PLAIN}"
  exit 1
fi

# 生成自签名证书(1年有效期)
echo -e "${YELLOW}生成自签名证书(1年有效期)...${PLAIN}"
openssl req -x509 -nodes -newkey rsa:2048 -days 365 -keyout /etc/hysteria2/cert/private.key -out /etc/hysteria2/cert/cert.crt -subj "/CN=$(curl -s ifconfig.me)"

# 配置系统参数
echo -e "${YELLOW}优化系统参数...${PLAIN}"
cat > /etc/sysctl.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=60
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=9
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_retries2=12
net.ipv4.ip_local_port_range=10000 65000
net.netfilter.nf_conntrack_tcp_timeout_established=7200
EOF
sysctl -p

# 修改生成端口和链接的部分
echo -e "${YELLOW}生成配置参数...${PLAIN}"
base_port=$((RANDOM % 10000 + 20000))
# 生成额外端口用于端口跳跃
hop_ports=""
for i in {1..4}; do
    next_port=$((base_port + i * 97))
    hop_ports="$hop_ports,$next_port"
done
all_ports="$base_port$hop_ports"
ports="$all_ports"  # 保持变量兼容性

password=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)
obfs_password=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)

# 创建配置文件
echo -e "${YELLOW}创建Hysteria2配置文件...${PLAIN}"
cat > /etc/hysteria2/config.yaml << EOF
listen: :$base_port

tls:
  cert: /etc/hysteria2/cert/cert.crt
  key: /etc/hysteria2/cert/private.key

auth:
  type: password
  password: $password

masquerade:
  type: proxy
  proxy:
    url: https://www.apple.com/
    rewriteHost: true
  file:
    dir: /var/www/html

bandwidth:
  up: 10 mbps
  down: 10 mbps

obfs:
  type: salamander
  salamander:
    password: $obfs_password

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 60s
  keepAlivePeriod: 5s
EOF

# 创建systemd服务
echo -e "${YELLOW}创建系统服务...${PLAIN}"
cat > /etc/systemd/system/hysteria2.service << EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria2/hysteria server -c /etc/hysteria2/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 配置Nginx
echo -e "${YELLOW}配置Nginx...${PLAIN}"
cat > /etc/nginx/conf.d/hysteria2.conf << EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    
    ssl_certificate /etc/hysteria2/cert/cert.crt;
    ssl_certificate_key /etc/hysteria2/cert/private.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

# 创建伪装页面
echo -e "${YELLOW}创建伪装页面...${PLAIN}"
cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <h1>Welcome to Nginx!</h1>
    <p>If you see this page, the nginx web server is successfully installed and working.</p>
</body>
</html>
EOF

# 创建管理脚本
echo -e "${YELLOW}创建管理脚本...${PLAIN}"
cat > /usr/local/bin/fff << 'EOF'
#!/bin/bash
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

show_menu() {
    clear
    echo -e "${GREEN}===============================${PLAIN}"
    echo -e "${GREEN}   Hysteria2 管理菜单 v1.0   ${PLAIN}"
    echo -e "${GREEN}===============================${PLAIN}"
    echo -e "${GREEN}1.${PLAIN} 查看服务状态"
    echo -e "${GREEN}2.${PLAIN} 显示分享链接"
    echo -e "${GREEN}3.${PLAIN} 重启服务"
    echo -e "${GREEN}4.${PLAIN} 查看配置"
    echo -e "${GREEN}5.${PLAIN} 卸载服务"
    echo -e "${GREEN}0.${PLAIN} 退出菜单"
    echo -e "${GREEN}===============================${PLAIN}"
    
    read -p "请选择操作 [0-5]: " choice
    
    case "$choice" in
        1)
            systemctl status hysteria2
            ;;
        2)
            generate_links
            ;;
        3)
            systemctl restart hysteria2
            echo -e "${GREEN}服务已重启${PLAIN}"
            ;;
        4)
            echo -e "${YELLOW}配置文件:${PLAIN} /etc/hysteria2/config.yaml"
            cat /etc/hysteria2/config.yaml
            ;;
        5)
            read -p "确定要卸载Hysteria2吗？(y/n): " confirm
            if [[ "$confirm" = "y" || "$confirm" = "Y" ]]; then
                uninstall_hysteria2
            fi
            ;;
        0)
            exit 0
            ;;
        *)
            echo -e "${RED}无效的选择${PLAIN}"
            ;;
    esac
    
    read -p "按任意键继续..." key
    show_menu
}

generate_links() {
    ip=$(curl -s4m8 ip.sb || curl -s6m8 ip.sb || curl -s4m8 ifconfig.me)
    config=$(cat /etc/hysteria2/config.yaml)
    port=$(echo "$config" | grep "listen:" | awk -F':' '{print $3}')
    password=$(echo "$config" | grep -A1 "password:" | tail -n1 | awk '{print $2}')
    obfs_password=$(echo "$config" | grep -A2 "salamander:" | grep "password:" | awk '{print $2}')
    
    echo -e "${GREEN}服务器信息:${PLAIN}"
    echo -e "${YELLOW}服务器IP:${PLAIN} $ip"
    echo -e "${YELLOW}端口:${PLAIN} $port"
    echo -e "${YELLOW}密码:${PLAIN} $password"
    echo -e "${YELLOW}混淆密码:${PLAIN} $obfs_password"
    
    # 生成端口跳跃范围
    hop_ports=""
    for i in {1..4}; do
        next_port=$((port + i * 97))
        hop_ports="$hop_ports,$next_port"
    done
    all_ports="$port$hop_ports"
    
    echo -e "${GREEN}分享链接:${PLAIN}"
    echo -e "hysteria2://$password@$ip:$port?insecure=1&obfs=salamander&obfs-password=$obfs_password&fastopen=1&up=10&down=10&sni=www.apple.com"
    echo -e "${GREEN}端口跳跃链接:${PLAIN}"
    echo -e "hysteria2://$password@$ip:$all_ports?insecure=1&obfs=salamander&obfs-password=$obfs_password&fastopen=1&up=10&down=10&sni=www.apple.com&hops=$all_ports"
    
    # 创建客户端配置
    mkdir -p /etc/hysteria2
    cat > /etc/hysteria2/client.yaml << EOCLIENT
server: $ip:$port
auth: $password
tls:
  insecure: true
  sni: www.apple.com
obfs:
  type: salamander
  salamander:
    password: $obfs_password
bandwidth:
  up: 10 mbps
  down: 10 mbps
fastOpen: true
hops:
  ports: ["$base_port", "$((base_port + 97))", "$((base_port + 97*2))", "$((base_port + 97*3))", "$((base_port + 97*4))"]
  interval: 10s
socks5:
  listen: 127.0.0.1:1080
http:
  listen: 127.0.0.1:8080
EOCLIENT
    
    echo -e "${GREEN}客户端配置已保存至:${PLAIN} /etc/hysteria2/client.yaml"
    echo -e "${YELLOW}提示: 端口跳跃功能需要确保所有端口($all_ports)都在防火墙中放行${PLAIN}"
}

uninstall_hysteria2() {
    systemctl stop hysteria2
    systemctl disable hysteria2
    rm -f /etc/systemd/system/hysteria2.service
    rm -rf /usr/local/bin/hysteria2
    rm -rf /etc/hysteria2
    rm -f /usr/local/bin/fff
    rm -f /usr/bin/fff
    rm -f /etc/nginx/conf.d/hysteria2.conf
    systemctl restart nginx
    echo -e "${GREEN}Hysteria2 已完全卸载${PLAIN}"
}

# 启动菜单
show_menu
EOF

chmod +x /usr/local/bin/fff
ln -sf /usr/local/bin/fff /usr/bin/fff

# 开放防火墙端口
echo -e "${YELLOW}配置防火墙...${PLAIN}"
# 将端口字符串转换为数组
IFS=',' read -ra PORT_ARRAY <<< "$ports"

# 检测云环境
is_cloud_server=0
if [ -f /sys/hypervisor/uuid ] && grep -q -i 'ec2\|amazon' /sys/hypervisor/uuid 2>/dev/null; then
    is_cloud_server=1
    cloud_provider="AWS"
elif [ -f /sys/devices/virtual/dmi/id/product_uuid ] && grep -q -i 'alibaba\|aliyun' /etc/hosts 2>/dev/null; then
    is_cloud_server=1
    cloud_provider="阿里云"
elif grep -q -i 'tencentcloud\|tencent-cloud' /etc/hosts 2>/dev/null; then
    is_cloud_server=1
    cloud_provider="腾讯云"
elif grep -q -i 'huaweicloud' /etc/hosts 2>/dev/null; then
    is_cloud_server=1
    cloud_provider="华为云"
fi

# 检测是否有防火墙工具并尝试开放端口
has_firewall=0
if command -v firewall-cmd &>/dev/null; then
    has_firewall=1
    echo -e "${GREEN}检测到firewalld防火墙，正在配置...${PLAIN}"
    for PORT in "${PORT_ARRAY[@]}"; do
        firewall-cmd --permanent --add-port="${PORT}/udp"
    done
    firewall-cmd --permanent --add-port=443/tcp
    firewall-cmd --reload
    echo -e "${GREEN}已配置firewalld防火墙规则${PLAIN}"
elif command -v ufw &>/dev/null; then
    has_firewall=1
    echo -e "${GREEN}检测到UFW防火墙，正在配置...${PLAIN}"
    for PORT in "${PORT_ARRAY[@]}"; do
        ufw allow "${PORT}/udp"
    done
    ufw allow 443/tcp
    ufw reload
    echo -e "${GREEN}已配置UFW防火墙规则${PLAIN}"
elif command -v iptables &>/dev/null; then
    has_firewall=1
    echo -e "${GREEN}检测到iptables防火墙，正在配置...${PLAIN}"
    for PORT in "${PORT_ARRAY[@]}"; do
        iptables -A INPUT -p udp --dport "${PORT}" -j ACCEPT
    done
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    if command -v iptables-save &>/dev/null; then
        iptables-save > /etc/iptables.rules
        echo -e "${GREEN}已配置iptables防火墙规则并保存${PLAIN}"
        
        # 创建持久化规则
        if [ -d "/etc/network/if-pre-up.d" ]; then
            cat > /etc/network/if-pre-up.d/iptablesload << 'EOF'
#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0
EOF
            chmod +x /etc/network/if-pre-up.d/iptablesload
            echo -e "${GREEN}已创建iptables启动加载规则${PLAIN}"
        fi
    else 
        echo -e "${YELLOW}已配置iptables防火墙规则，但可能需要手动保存${PLAIN}"
    fi
else
    # 没有检测到防火墙但也不一定是云服务器
    if [ $is_cloud_server -eq 0 ]; then
        # 提示安装防火墙工具
        echo -e "${YELLOW}未检测到防火墙工具，是否需要安装？[y/n]${PLAIN}"
        read -r install_firewall
        if [[ "$install_firewall" =~ ^[Yy]$ ]]; then
            if [ -f /etc/debian_version ]; then
                apt update
                apt install -y ufw
                ufw allow ssh
                ufw enable
                for PORT in "${PORT_ARRAY[@]}"; do
                    ufw allow "${PORT}/udp"
                done
                ufw allow 443/tcp
                ufw reload
                echo -e "${GREEN}已安装并配置UFW防火墙${PLAIN}"
            elif [ -f /etc/redhat-release ]; then
                yum -y install firewalld
                systemctl enable firewalld
                systemctl start firewalld
                for PORT in "${PORT_ARRAY[@]}"; do
                    firewall-cmd --permanent --add-port="${PORT}/udp"
                done
                firewall-cmd --permanent --add-port=443/tcp
                firewall-cmd --reload
                echo -e "${GREEN}已安装并配置firewalld防火墙${PLAIN}"
            else
                echo -e "${RED}无法确定系统类型，请手动安装防火墙工具${PLAIN}"
            fi
        fi
    fi
fi

# 云服务器安全组配置指南
if [ $is_cloud_server -eq 1 ]; then
    echo -e "\n${YELLOW}================================${PLAIN}"
    echo -e "${YELLOW}检测到您正在使用${PLAIN} ${GREEN}$cloud_provider${PLAIN} ${YELLOW}云服务器${PLAIN}"
    echo -e "${YELLOW}================================${PLAIN}"
    echo -e "${RED}重要提示：云服务器还需要在云控制台配置安全组规则！${PLAIN}\n"
    
    echo -e "${GREEN}【$cloud_provider 安全组配置步骤】${PLAIN}"
    case $cloud_provider in
        "阿里云")
            echo -e "1. 登录阿里云控制台: https://ecs.console.aliyun.com/"
            echo -e "2. 点击左侧菜单[网络与安全] -> [安全组]"
            echo -e "3. 找到您的实例所在安全组，点击[配置规则]"
            echo -e "4. 点击[添加安全组规则]，添加以下规则:"
            ;;
        "腾讯云")
            echo -e "1. 登录腾讯云控制台: https://console.cloud.tencent.com/"
            echo -e "2. 进入[云服务器] -> [安全组]"
            echo -e "3. 选择您的安全组，点击[修改规则]"
            echo -e "4. 点击[添加规则]，添加以下规则:"
            ;;
        "华为云")
            echo -e "1. 登录华为云控制台: https://console.huaweicloud.com/"
            echo -e "2. 进入[弹性云服务器] -> [安全组]"
            echo -e "3. 选择您的安全组，点击[配置规则]"
            echo -e "4. 点击[添加规则]，添加以下规则:"
            ;;
        *)
            echo -e "1. 登录您的云服务控制台"
            echo -e "2. 找到安全组/防火墙配置"
            echo -e "3. 添加以下入站规则:"
            ;;
    esac
    
    echo -e "\n${YELLOW}UDP规则:${PLAIN}"
    for PORT in "${PORT_ARRAY[@]}"; do
        echo -e "   协议类型:UDP  端口范围:${PORT}/${PORT}  来源:0.0.0.0/0"
    done
    echo -e "${YELLOW}TCP规则:${PLAIN}"
    echo -e "   协议类型:TCP  端口范围:443/443  来源:0.0.0.0/0\n"
    
    echo -e "${RED}注意: 如不配置安全组规则，服务将无法正常连接！${PLAIN}"
    echo -e "${YELLOW}================================${PLAIN}\n"
else
    # 提示端口开放情况
    echo -e "\n${YELLOW}请确保以下端口已开放:${PLAIN}"
    echo -e "${YELLOW}UDP端口: $ports${PLAIN}"
    echo -e "${YELLOW}TCP端口: 443${PLAIN}\n"
fi

# 重启服务
echo -e "${YELLOW}启动服务...${PLAIN}"
systemctl daemon-reload
systemctl enable hysteria2
systemctl restart hysteria2
systemctl restart nginx || systemctl start nginx

# 验证服务状态
echo -e "${YELLOW}检查服务状态...${PLAIN}"
if systemctl is-active --quiet hysteria2; then
    echo -e "${GREEN}Hysteria2 服务已成功启动！${PLAIN}"
else
    echo -e "${RED}Hysteria2 服务启动失败，请检查日志：journalctl -u hysteria2 -n 50${PLAIN}"
    exit 1
fi

# 生成分享链接
ip=$(curl -s4m8 ip.sb || curl -s6m8 ip.sb || curl -s4m8 ifconfig.me)

echo -e "${GREEN}====== Hysteria2 安装完成 ======${PLAIN}"
echo -e "${GREEN}服务器IP:${PLAIN} $ip"
echo -e "${GREEN}端口:${PLAIN} $base_port"
echo -e "${GREEN}密码:${PLAIN} $password"
echo -e "${GREEN}混淆密码:${PLAIN} $obfs_password"
echo -e "${GREEN}端口跳跃:${PLAIN} $ports"
echo -e "${GREEN}=============================${PLAIN}"

# 修改生成分享链接的部分，确保兼容性
echo -e "${GREEN}分享链接:${PLAIN} hysteria2://$password@$ip:$base_port?insecure=1&obfs=salamander&obfs-password=$obfs_password&fastopen=1&up=10&down=10&sni=www.apple.com"
echo -e "${GREEN}端口跳跃链接:${PLAIN} hysteria2://$password@$ip:$all_ports?insecure=1&obfs=salamander&obfs-password=$obfs_password&fastopen=1&up=10&down=10&sni=www.apple.com&hop=1"

# 添加防火墙放行提示
echo -e "\n${YELLOW}===== 防火墙端口放行指南 =====${PLAIN}"
echo -e "${GREEN}请确保以下端口已在防火墙中开放:${PLAIN}"
echo -e "UDP 端口: $ports (Hysteria2)"
echo -e "TCP 端口: 443 (HTTPS/Nginx)"
echo -e "\n${YELLOW}各类防火墙放行命令:${PLAIN}"
echo -e "${GREEN}1. iptables:${PLAIN}"
for PORT in ${ports//,/ }; do
  echo "iptables -A INPUT -p udp --dport $PORT -j ACCEPT"
done
echo "iptables -A INPUT -p tcp --dport 443 -j ACCEPT"
echo -e "\n${GREEN}2. firewalld(CentOS/RHEL):${PLAIN}"
for PORT in ${ports//,/ }; do
  echo "firewall-cmd --permanent --add-port=$PORT/udp"
done
echo "firewall-cmd --permanent --add-port=443/tcp"
echo "firewall-cmd --reload"
echo -e "\n${GREEN}3. ufw(Debian/Ubuntu):${PLAIN}"
for PORT in ${ports//,/ }; do
  echo "ufw allow $PORT/udp"
done
echo "ufw allow 443/tcp"
echo "ufw reload"
echo -e "\n${GREEN}4. Alibaba Cloud/腾讯云/华为云安全组:${PLAIN}"
echo "请登录云平台控制台，在安全组规则中放行上述UDP及TCP端口"

echo -e "${GREEN}=============================${PLAIN}"
echo -e "${GREEN}使用 'fff' 命令进入管理菜单${PLAIN}"
echo -e "${GREEN}=============================${PLAIN}"

# 生成可直接复制的配置文件
echo -e "\n${YELLOW}===== 服务器配置 (server_config.yaml) =====${PLAIN}"
cat << EOF
listen: :$base_port

tls:
  cert: /etc/hysteria2/cert/cert.crt
  key: /etc/hysteria2/cert/private.key

auth:
  type: password
  password: $password

masquerade:
  type: proxy
  proxy:
    url: https://www.apple.com/
    rewriteHost: true

bandwidth:
  up: 10 mbps
  down: 10 mbps

obfs:
  type: salamander
  salamander:
    password: $obfs_password

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 60s
  keepAlivePeriod: 5s
EOF

echo -e "\n${YELLOW}===== 客户端配置 (client_config.yaml) =====${PLAIN}"
cat << EOF
server: $ip:$base_port

auth: $password

tls:
  insecure: true
  sni: www.apple.com

obfs:
  type: salamander
  salamander:
    password: $obfs_password

bandwidth:
  up: 10 mbps
  down: 10 mbps

fastOpen: true

hopInterval: 30

retry: 3

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080
EOF

# 生成优化系统参数
echo -e "\n${YELLOW}===== 优化系统参数 (sysctl.conf) =====${PLAIN}"
cat << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=60
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=9
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_retries2=12
net.ipv4.ip_local_port_range=10000 65000
net.netfilter.nf_conntrack_tcp_timeout_established=7200
EOF

# 创建监控脚本
cat > /usr/local/bin/hysteria2-monitor.sh << 'EOF'
#!/bin/bash
check_and_restart() {
  if ! systemctl is-active --quiet hysteria2; then
    systemctl restart hysteria2
    echo "$(date) - Hysteria2 服务已重启" >> /var/log/hysteria2-monitor.log
  fi
}
check_and_restart
EOF
chmod +x /usr/local/bin/hysteria2-monitor.sh

# 添加定时任务每分钟检查
(crontab -l 2>/dev/null | grep -v "hysteria2-monitor.sh"; echo "* * * * * /usr/local/bin/hysteria2-monitor.sh") | crontab -

echo -e "\n${GREEN}已添加自动监控脚本，每分钟检查服务状态并自动重启${PLAIN}" 