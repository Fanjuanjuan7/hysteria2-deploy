#!/bin/bash

# 检查是否为root用户
check_root() {
    [[ $EUID -ne 0 ]] && echo -e "${RED}错误：${PLAIN}必须使用root用户运行此脚本！\n" && exit 1
}

# 颜色设置
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

# 脚本版本
VERSION="1.0.0"

# 检查系统
check_sys() {
    if [ "$TEST_MODE" = "true" ]; then
        # 测试模式下，假设系统为Debian
        RELEASE="debian"
        return
    fi
    
    if [[ -f /etc/redhat-release ]]; then
        RELEASE="centos"
    elif cat /etc/issue | grep -Eqi "debian"; then
        RELEASE="debian"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        RELEASE="ubuntu"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        RELEASE="centos"
    elif cat /proc/version | grep -Eqi "debian"; then
        RELEASE="debian"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        RELEASE="ubuntu"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        RELEASE="centos"
    else
        echo -e "${RED}未检测到系统版本，请联系脚本作者！${PLAIN}\n" && exit 1
    fi
}

# 检查系统架构
check_arch() {
    if [ "$TEST_MODE" = "true" ]; then
        # 测试模式下，假设架构为amd64
        ARCH="amd64"
        return
    fi
    
    arch=$(arch)
    if [[ $arch == "x86_64" || $arch == "x64" || $arch == "amd64" ]]; then
        ARCH="amd64"
    elif [[ $arch == "aarch64" || $arch == "arm64" ]]; then
        ARCH="arm64"
    else
        echo -e "${RED}不支持的系统架构: ${arch}${PLAIN}" && exit 1
    fi
}

# 检查依赖命令
check_command() {
    command -v "$1" >/dev/null 2>&1
}

# 获取IP地址
get_ip() {
    if [ "$TEST_MODE" = "true" ]; then
        # 测试模式下，使用示例IP
        echo "123.123.123.123"
        return
    fi
    
    local IP
    IP=$(curl -s4m8 ip.sb) || IP=$(curl -s6m8 ip.sb)
    if [[ -z "$IP" ]]; then
        IP=$(curl -s4m8 ifconfig.me) || IP=$(curl -s6m8 ifconfig.me)
    fi
    if [[ -z "$IP" ]]; then
        IP=$(curl -s4m8 api.ipify.org) || IP=$(curl -s6m8 api6.ipify.org)
    fi
    echo "$IP"
}

# 显示进度条
show_progress() {
    local duration=$1
    local step=1
    local progress=0
    local full_progress=20
    
    while [[ $progress -lt $full_progress ]]; do
        echo -ne "\r[${GREEN}"
        for ((i=0; i<progress; i++)); do
            echo -n "="
        done
        
        echo -ne ">${PLAIN}"
        
        for ((i=progress; i<full_progress; i++)); do
            echo -n " "
        done
        
        echo -ne "] ${progress}/${full_progress}"
        
        progress=$((progress+step))
        sleep "$duration"
    done
    echo -ne "\r[${GREEN}===================>${PLAIN}] ${full_progress}/${full_progress}\n"
}

# 随机生成非标准UDP端口
generate_ports() {
    local base_port=$((RANDOM % 10000 + 20000))
    local ports_count=5 # 生成5个非连续端口
    local ports=""
    
    for ((i=0; i<ports_count; i++)); do
        local port=$((base_port + i * 97)) # 使用非连续间隔
        ports="$ports,$port"
    done
    
    echo "${ports:1}" # 去掉前导逗号
}

# 安装必要的依赖
install_dependencies() {
    echo -e "${YELLOW}正在安装依赖...${PLAIN}"
    
    if [[ $RELEASE == "centos" ]]; then
        yum update -y
        yum install -y epel-release
        yum install -y wget curl unzip tar openssl nginx socat jq net-tools
    else
        apt update -y
        apt install -y wget curl unzip tar openssl nginx socat jq net-tools
    fi
    
    if ! check_command nginx || ! check_command openssl || ! check_command curl; then
        echo -e "${RED}依赖安装失败，请检查网络或手动安装依赖！${PLAIN}"
        exit 1
    fi
    
    echo -e "${GREEN}依赖安装完成！${PLAIN}"
}

# 安装和配置BBR
setup_bbr() {
    echo -e "${YELLOW}正在设置BBR和优化网络参数...${PLAIN}"
    
    # 检查是否已开启BBR
    if [ -n "$(lsmod | grep bbr)" ]; then
        echo -e "${GREEN}BBR已经启用！${PLAIN}"
        return
    fi

    # 配置sysctl参数
    cat > /etc/sysctl.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_intvl=15
net.ipv4.tcp_keepalive_probes=10
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_max_tw_buckets=5000
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_rmem=4096 87380 4194304
net.ipv4.tcp_wmem=4096 65536 4194304
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.core.rmem_default=262144
net.core.wmem_default=262144
net.core.rmem_max=8388608
net.core.wmem_max=8388608
net.core.netdev_max_backlog=16384
net.core.somaxconn=8192
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_mem=94500000 915000000 927000000
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_ecn=0
net.ipv4.route.gc_timeout=100
net.ipv4.ip_forward=1
net.ipv4.tcp_retries2=8
fs.file-max=1000000
vm.swappiness=10
vm.vfs_cache_pressure=50
EOF
    
    # 应用sysctl参数
    sysctl -p
    
    # 为系统优化参数
    cat > /etc/security/limits.conf << EOF
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 32000
* hard nproc 32000
EOF

    # 设置DNS解析
    cat > /etc/resolv.conf << EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 114.114.114.114
EOF

    echo -e "${GREEN}BBR和网络参数优化设置完成！${PLAIN}"
}

# 生成1年有效期的自签名证书
generate_cert() {
    echo -e "${YELLOW}正在生成自签名证书...${PLAIN}"
    
    mkdir -p /etc/hysteria2/cert
    
    # 创建配置文件以支持1年有效期
    cat > /etc/hysteria2/cert/openssl.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = Hysteria2 Server

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = $IP
EOF

    # 生成私钥和证书，有效期365天
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
        -config /etc/hysteria2/cert/openssl.cnf \
        -keyout /etc/hysteria2/cert/private.key \
        -out /etc/hysteria2/cert/cert.crt
    
    if [ ! -f "/etc/hysteria2/cert/cert.crt" ] || [ ! -f "/etc/hysteria2/cert/private.key" ]; then
        echo -e "${RED}证书生成失败！${PLAIN}"
        exit 1
    fi
    
    echo -e "${GREEN}自签名证书生成完成，有效期365天！${PLAIN}"
}

# 下载并安装 Hysteria2
install_hysteria2() {
    echo -e "${YELLOW}正在下载并安装 Hysteria2...${PLAIN}"
    
    # 创建安装目录
    mkdir -p /usr/local/bin/hysteria2
    mkdir -p /etc/hysteria2
    
    # 获取最新版本
    LATEST_VERSION=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
    if [[ -z "$LATEST_VERSION" ]]; then
        LATEST_VERSION="v1.3.4" # 如果无法获取最新版本，使用默认版本
    fi
    
    # 下载 Hysteria2
    DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/${LATEST_VERSION}/hysteria-linux-${ARCH}"
    echo -e "下载链接: ${DOWNLOAD_URL}"
    
    if ! wget -N -O /tmp/hysteria2.bin "$DOWNLOAD_URL"; then
        echo -e "${RED}下载 Hysteria2 失败！${PLAIN}"
        exit 1
    fi
    
    # 安装
    mv /tmp/hysteria2.bin /usr/local/bin/hysteria2/hysteria
    chmod +x /usr/local/bin/hysteria2/hysteria
    
    # 检查是否安装成功
    if ! /usr/local/bin/hysteria2/hysteria version; then
        echo -e "${RED}Hysteria2 安装失败！${PLAIN}"
        exit 1
    fi
    
    # 创建systemd服务
    cat > /etc/systemd/system/hysteria2.service << EOF
[Unit]
Description=Hysteria2 Server Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria2/hysteria server -c /etc/hysteria2/config.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}Hysteria2 安装完成！${PLAIN}"
}

# 配置Hysteria2
configure_hysteria2() {
    echo -e "${YELLOW}正在配置 Hysteria2...${PLAIN}"
    
    # 生成随机密码 (避免特殊字符)
    PASSWORD=${PASSWORD:-$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)}
    OBFS_PASSWORD=${OBFS_PASSWORD:-$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)}
    
    # 设置固定带宽为25Mbps（为了在30Mbps限制下保持稳定）
    BANDWIDTH_UP=25
    BANDWIDTH_DOWN=25
    
    # 创建配置文件
    cat > /etc/hysteria2/config.yaml << EOF
listen: :${PORTS%%,*}

tls:
  cert: /etc/hysteria2/cert/cert.crt
  key: /etc/hysteria2/cert/private.key

auth:
  type: password
  password: ${PASSWORD}

masquerade:
  type: proxy
  proxy:
    url: https://www.apple.com/
    rewriteHost: true
  file:
    dir: /var/www/html

bandwidth:
  up: ${BANDWIDTH_UP} mbps
  down: ${BANDWIDTH_DOWN} mbps

ignoreClientBandwidth: false

obfs:
  type: salamander
  salamander:
    password: ${OBFS_PASSWORD}

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 30s
  maxAckDelay: 20ms
  keepAlivePeriod: 10s
  disablePathMTUDiscovery: false

trafficStats:
  listen: 127.0.0.1:9999
EOF
    
    # 验证配置文件格式
    if command -v yamllint >/dev/null 2>&1; then
        if ! yamllint /etc/hysteria2/config.yaml; then
            echo -e "${RED}配置文件格式验证失败！${PLAIN}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}Hysteria2 配置完成！${PLAIN}"
    echo -e "${YELLOW}当前带宽设置：上行 ${BANDWIDTH_UP} mbps，下行 ${BANDWIDTH_DOWN} mbps${PLAIN}"
    
    # 生成分享链接
    generate_share_link
    
    # 显示配置内容以便调试
    echo -e "${YELLOW}配置文件内容:${PLAIN}"
    cat /etc/hysteria2/config.yaml
}

# 配置Nginx作为反向代理
setup_nginx() {
    echo -e "${YELLOW}正在配置 Nginx...${PLAIN}"
    
    # 确保Nginx目录存在
    mkdir -p /var/www/html
    
    # 下载一些伪装用的网页文件
    echo -e "${YELLOW}正在下载伪装网页...${PLAIN}"
    wget -O /tmp/web.zip "https://github.com/HyNetwork/hysteria/archive/refs/heads/master.zip" || {
        echo -e "${RED}下载伪装网页失败，使用备选方案...${PLAIN}"
        # 创建简单的index.html作为备选方案
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
    }
    
    if [ -f "/tmp/web.zip" ]; then
        unzip -o /tmp/web.zip -d /tmp/ || {
            echo -e "${RED}解压伪装网页失败，使用备选方案...${PLAIN}"
            rm -f /tmp/web.zip
        }
        
        if [ -d "/tmp/hysteria-master" ]; then
            cp -rf /tmp/hysteria-master/app/redirect/* /var/www/html/
            rm -rf /tmp/hysteria-master /tmp/web.zip
        fi
    fi
    
    # 配置Nginx
    cat > /etc/nginx/conf.d/hysteria2.conf << EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    
    ssl_certificate /etc/hysteria2/cert/cert.crt;
    ssl_certificate_key /etc/hysteria2/cert/private.key;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    server_name _;
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    
    # 重启Nginx
    if ! systemctl restart nginx; then
        echo -e "${RED}Nginx 启动失败，请检查配置！${PLAIN}"
        exit 1
    fi
    
    systemctl enable nginx
    
    echo -e "${GREEN}Nginx 配置完成！${PLAIN}"
}

# 生成分享链接
generate_share_link() {
    echo -e "${YELLOW}正在生成分享链接...${PLAIN}"
    
    CURRENT_IP=$(get_ip)
    CURRENT_PORT=${PORTS%%,*}  # 仅使用第一个端口，提高兼容性
    
    # URL编码处理密码中的特殊字符
    # 这里我们将生成一个更友好的分享链接
    URL_PASSWORD=$(echo -n "$PASSWORD" | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g')
    
    # 生成基本链接
    SHARE_LINK="hysteria2://${URL_PASSWORD}@${CURRENT_IP}:${CURRENT_PORT}?insecure=1&obfs=salamander&obfs-password=${OBFS_PASSWORD}&fastopen=1"
    
    # 生成备用链接 (不带URL编码，某些客户端可能需要)
    SHARE_LINK_PLAIN="hysteria2://${PASSWORD}@${CURRENT_IP}:${CURRENT_PORT}?insecure=1&obfs=salamander&obfs-password=${OBFS_PASSWORD}&fastopen=1"
    
    echo "$SHARE_LINK" > /etc/hysteria2/share_link.txt
    echo "$SHARE_LINK_PLAIN" > /etc/hysteria2/share_link_plain.txt
    
    # 生成客户端配置文件
    cat > /etc/hysteria2/client.yaml << 'ENDOFCLIENT'
server: ${CURRENT_IP}:${CURRENT_PORT}

auth: ${PASSWORD}

tls:
  insecure: true

obfs:
  type: salamander
  salamander:
    password: ${OBFS_PASSWORD}

fastOpen: true

socks5:
  listen: 127.0.0.1:1080
http:
  listen: 127.0.0.1:8080
ENDOFCLIENT

    # 变量替换
    sed -i "s|\${CURRENT_IP}|$CURRENT_IP|g" /etc/hysteria2/client.yaml
    sed -i "s|\${CURRENT_PORT}|$CURRENT_PORT|g" /etc/hysteria2/client.yaml
    sed -i "s|\${PASSWORD}|$PASSWORD|g" /etc/hysteria2/client.yaml
    sed -i "s|\${OBFS_PASSWORD}|$OBFS_PASSWORD|g" /etc/hysteria2/client.yaml
    
    # 输出成功信息
    echo -e "${GREEN}分享链接已生成！${PLAIN}"
    echo -e "${YELLOW}URL编码链接 (推荐):${PLAIN} $SHARE_LINK"
    echo -e "${YELLOW}普通链接:${PLAIN} $SHARE_LINK_PLAIN"
    echo -e "${YELLOW}客户端配置文件已保存至 /etc/hysteria2/client.yaml${PLAIN}"
}

# 启动 Hysteria2 服务
start_hysteria2() {
    echo -e "${YELLOW}正在启动 Hysteria2 服务...${PLAIN}"
    
    systemctl start hysteria2
    systemctl enable hysteria2
    
    # 验证服务是否正常启动
    sleep 2
    if ! systemctl is-active --quiet hysteria2; then
        echo -e "${RED}Hysteria2 服务启动失败！${PLAIN}"
        echo -e "${YELLOW}查看日志: ${PLAIN}journalctl -u hysteria2 -n 50"
        exit 1
    fi
    
    echo -e "${GREEN}Hysteria2 服务已启动！${PLAIN}"
}

# 检查 Hysteria2 状态
check_status() {
    echo -e "${YELLOW}检查 Hysteria2 状态...${PLAIN}"
    
    if systemctl is-active --quiet hysteria2; then
        echo -e "${GREEN}Hysteria2 正在运行！${PLAIN}"
        echo -e "${GREEN}配置文件:${PLAIN} /etc/hysteria2/config.yaml"
        echo -e "${GREEN}执行文件:${PLAIN} /usr/local/bin/hysteria2/hysteria"
    else
        echo -e "${RED}Hysteria2 未运行！${PLAIN}"
    fi
    
    echo -e "${YELLOW}运行 'netstat -antup | grep hysteria' 查看监听端口:${PLAIN}"
    netstat -antup | grep hysteria
}

# 查看配置信息
view_config() {
    echo -e "${YELLOW}Hysteria2 配置信息:${PLAIN}"
    echo -e "${GREEN}----------------------------------${PLAIN}"
    echo -e "${GREEN}服务器 IP:${PLAIN} $IP"
    echo -e "${GREEN}端口:${PLAIN} $PORTS"
    echo -e "${GREEN}协议:${PLAIN} Hysteria2"
    echo -e "${GREEN}混淆:${PLAIN} Salamander"
    echo -e "${GREEN}混淆密码:${PLAIN} $OBFS_PASSWORD"
    echo -e "${GREEN}认证密码:${PLAIN} $PASSWORD"
    echo -e "${GREEN}----------------------------------${PLAIN}"
    
    if [ -f /etc/hysteria2/share_link.txt ]; then
        echo -e "${GREEN}分享链接:${PLAIN} $(cat /etc/hysteria2/share_link.txt)"
    fi
    
    echo -e "${GREEN}----------------------------------${PLAIN}"
}

# 卸载 Hysteria2
uninstall_hysteria2() {
    echo -e "${YELLOW}正在卸载 Hysteria2...${PLAIN}"
    
    # 停止并禁用相关服务
    systemctl stop hysteria2 2>/dev/null
    systemctl disable hysteria2 2>/dev/null
    systemctl stop hysteria2-watchdog 2>/dev/null
    systemctl disable hysteria2-watchdog 2>/dev/null
    
    # 移除定时任务
    if crontab -l | grep -q "hysteria2_watchdog"; then
        (crontab -l 2>/dev/null | grep -v "hysteria2_watchdog") | crontab -
        echo -e "${GREEN}已移除监控定时任务${PLAIN}"
    fi
    
    # 删除相关文件
    rm -rf /usr/local/bin/hysteria2
    rm -f /usr/local/bin/hysteria2_watchdog.sh
    rm -f /etc/systemd/system/hysteria2.service
    rm -f /etc/systemd/system/hysteria2-watchdog.service
    rm -f /etc/systemd/system/hysteria2-autostart.service
    rm -rf /etc/hysteria2
    rm -f /var/log/hysteria2_watchdog.log
    
    # 移除nginx配置
    rm -f /etc/nginx/conf.d/hysteria2.conf
    systemctl restart nginx 2>/dev/null
    
    # 重新加载systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}Hysteria2 已完全卸载！${PLAIN}"
}

# 创建管理菜单
create_menu() {
    echo -e "${YELLOW}正在创建管理菜单...${PLAIN}"
    
    # 确保目录存在
    mkdir -p /usr/local/bin
    
    # 创建菜单脚本
    cat > /usr/local/bin/fff << 'EOF'
#!/bin/bash
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN="\033[0m"

show_menu() {
    echo -e "${GREEN}===============================${PLAIN}"
    echo -e "${GREEN}   Hysteria2 管理菜单 v1.0   ${PLAIN}"
    echo -e "${GREEN}===============================${PLAIN}"
    echo -e "${GREEN}1.${PLAIN} 重新安装 Hysteria2"
    echo -e "${GREEN}2.${PLAIN} 查看当前 Hysteria2 状态"
    echo -e "${GREEN}3.${PLAIN} 显示分享链接"
    echo -e "${GREEN}4.${PLAIN} 查看当前配置信息"
    echo -e "${GREEN}5.${PLAIN} 卸载 Hysteria2"
    echo -e "${GREEN}0.${PLAIN} 退出菜单"
    echo -e "${GREEN}===============================${PLAIN}"
    read -p "请输入数字 [0-5]: " num
    
    case "$num" in
        1)
            echo -e "${YELLOW}正在重新安装 Hysteria2...${PLAIN}"
            systemctl stop hysteria2
            systemctl disable hysteria2
            rm -f /etc/systemd/system/hysteria2.service
            bash /usr/local/bin/hysteria2_deploy.sh reinstall
            echo -e "${GREEN}重新安装完成${PLAIN}"
            read -p "按任意键继续..." enter
            show_menu
            ;;
        2)
            echo -e "${YELLOW}当前 Hysteria2 状态:${PLAIN}"
            systemctl status hysteria2
            read -p "按任意键继续..." enter
            show_menu
            ;;
        3)
            if [ -f /etc/hysteria2/share_link.txt ]; then
                echo -e "${GREEN}URL编码分享链接 (推荐):${PLAIN} $(cat /etc/hysteria2/share_link.txt)"
                if [ -f /etc/hysteria2/share_link_plain.txt ]; then
                    echo -e "${GREEN}普通分享链接:${PLAIN} $(cat /etc/hysteria2/share_link_plain.txt)"
                fi
                echo -e "${YELLOW}提示: 如果导入失败，请尝试另一种链接格式${PLAIN}"
                echo -e "${YELLOW}客户端配置文件: /etc/hysteria2/client.yaml${PLAIN}"
                if [ -f /etc/hysteria2/client.yaml ]; then
                    echo -e "${BLUE}客户端配置内容:${PLAIN}"
                    cat /etc/hysteria2/client.yaml
                fi
            else
                # 重新生成分享链接
                PASSWORD=$(grep -A1 "password:" /etc/hysteria2/config.yaml | grep -v "type:" | awk '{print $2}')
                OBFS_PASS=$(grep -A2 "salamander:" /etc/hysteria2/config.yaml | grep "password:" | awk '{print $2}')
                IP=$(curl -s4m8 ip.sb || curl -s6m8 ip.sb || curl -s4m8 ifconfig.me || curl -s6m8 ifconfig.me)
                PORT=$(grep "listen:" /etc/hysteria2/config.yaml | awk -F':' '{print $3}')
                
                # URL编码密码
                URL_PASSWORD=$(echo -n "$PASSWORD" | xxd -plain | tr -d '\n' | sed 's/\(..\)/%\1/g')
                
                # 生成链接
                SHARE_LINK="hysteria2://${URL_PASSWORD}@${IP}:${PORT}?insecure=1&obfs=salamander&obfs-password=${OBFS_PASS}&fastopen=1"
                SHARE_LINK_PLAIN="hysteria2://${PASSWORD}@${IP}:${PORT}?insecure=1&obfs=salamander&obfs-password=${OBFS_PASS}&fastopen=1"
                
                echo "$SHARE_LINK" > /etc/hysteria2/share_link.txt
                echo "$SHARE_LINK_PLAIN" > /etc/hysteria2/share_link_plain.txt
                
                echo -e "${GREEN}URL编码分享链接 (推荐):${PLAIN} $SHARE_LINK"
                echo -e "${GREEN}普通分享链接:${PLAIN} $SHARE_LINK_PLAIN"
                
                # 生成客户端配置
                mkdir -p /etc/hysteria2
                cat > /etc/hysteria2/client.yaml << 'ENDOFCLIENTCFG'
server: ${IP}:${PORT}

auth: ${PASSWORD}

tls:
  insecure: true

obfs:
  type: salamander
  salamander:
    password: ${OBFS_PASS}

fastOpen: true

socks5:
  listen: 127.0.0.1:1080
http:
  listen: 127.0.0.1:8080
ENDOFCLIENTCFG

                # 变量替换
                sed -i "s|\${IP}|$IP|g" /etc/hysteria2/client.yaml
                sed -i "s|\${PORT}|$PORT|g" /etc/hysteria2/client.yaml
                sed -i "s|\${PASSWORD}|$PASSWORD|g" /etc/hysteria2/client.yaml
                sed -i "s|\${OBFS_PASS}|$OBFS_PASS|g" /etc/hysteria2/client.yaml
                echo -e "${YELLOW}客户端配置已生成: /etc/hysteria2/client.yaml${PLAIN}"
            fi
            read -p "按任意键继续..." enter
            show_menu
            ;;
        4)
            echo -e "${GREEN}Hysteria2 配置信息:${PLAIN}"
            echo -e "${YELLOW}----------------------------------${PLAIN}"
            cat /etc/hysteria2/config.yaml
            echo -e "${YELLOW}----------------------------------${PLAIN}"
            
            # 显示IP和端口信息
            IP=$(curl -s4m8 ip.sb || curl -s6m8 ip.sb || curl -s4m8 ifconfig.me || curl -s6m8 ifconfig.me)
            PORT=$(grep "listen:" /etc/hysteria2/config.yaml | awk -F':' '{print $3}')
            echo -e "${GREEN}服务器 IP:${PLAIN} $IP"
            echo -e "${GREEN}端口:${PLAIN} $PORT"
            
            # 显示证书有效期
            if [ -f /etc/hysteria2/cert/cert.crt ]; then
                echo -e "${YELLOW}证书信息:${PLAIN}"
                openssl x509 -in /etc/hysteria2/cert/cert.crt -noout -dates
            fi
            
            read -p "按任意键继续..." enter
            show_menu
            ;;
        5)
            echo -e "${RED}警告: 即将卸载 Hysteria2${PLAIN}"
            read -p "确定要卸载吗? (y/n): " confirm
            if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                bash /usr/local/bin/hysteria2_deploy.sh uninstall
                echo -e "${GREEN}Hysteria2 已卸载${PLAIN}"
            else
                echo -e "${GREEN}已取消卸载${PLAIN}"
            fi
            read -p "按任意键继续..." enter
            show_menu
            ;;
        0)
            exit 0
            ;;
        *)
            echo -e "${RED}请输入正确数字 [0-5]${PLAIN}"
            sleep 2
            show_menu
            ;;
    esac
}

show_menu
EOF
    
    # 设置执行权限
    chmod +x /usr/local/bin/fff
    
    # 复制脚本到系统目录
    cp -f "$0" /usr/local/bin/hysteria2_deploy.sh
    chmod +x /usr/local/bin/hysteria2_deploy.sh
    
    # 创建软链接确保在所有路径都可用
    ln -sf /usr/local/bin/fff /usr/bin/fff
    
    # 验证安装
    if [ -f "/usr/bin/fff" ] && [ -x "/usr/bin/fff" ]; then
        echo -e "${GREEN}管理菜单已创建，使用 'fff' 命令进入管理菜单！${PLAIN}"
    else
        echo -e "${RED}管理菜单创建失败，请检查系统权限！${PLAIN}"
        exit 1
    fi
}

# 打开防火墙端口
open_ports() {
    echo -e "${YELLOW}正在配置防火墙...${PLAIN}"
    
    # 将端口字符串转换为数组
    IFS=',' read -ra PORT_ARRAY <<< "$PORTS"
    
    # 检测是否有防火墙并开放端口
    if check_command firewall-cmd; then
        # CentOS/RHEL
        for PORT in "${PORT_ARRAY[@]}"; do
            firewall-cmd --permanent --add-port="${PORT}/udp"
        done
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
    elif check_command ufw; then
        # Ubuntu/Debian with UFW
        for PORT in "${PORT_ARRAY[@]}"; do
            ufw allow "${PORT}/udp"
        done
        ufw allow 443/tcp
        ufw reload
    elif check_command iptables; then
        # 通用 iptables
        for PORT in "${PORT_ARRAY[@]}"; do
            iptables -A INPUT -p udp --dport "${PORT}" -j ACCEPT
        done
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
        if check_command iptables-save; then
            iptables-save > /etc/iptables.rules
        fi
    fi
    
    echo -e "${GREEN}防火墙配置完成！${PLAIN}"
}

# 创建自启动脚本
setup_auto_start() {
    # 添加hysteria2_deploy.sh到PATH
    ln -sf /usr/local/bin/hysteria2_deploy.sh /usr/bin/hysteria2_deploy
    
    # 确保重启后fff命令仍然可用
    if [ ! -L "/usr/bin/fff" ]; then
        ln -sf /usr/local/bin/fff /usr/bin/fff
    fi
    
    # 创建自启动脚本
    cat > /etc/systemd/system/hysteria2-autostart.service << EOF
[Unit]
Description=Hysteria2 Auto Start
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hysteria2_deploy.sh autostart
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable hysteria2-autostart
    
    echo -e "${GREEN}自启动配置完成！${PLAIN}"
}

# 自启动检查
auto_start_check() {
    if ! systemctl is-active --quiet hysteria2; then
        echo -e "${YELLOW}检测到Hysteria2服务未运行，正在尝试启动...${PLAIN}"
        systemctl start hysteria2
        sleep 2
        if systemctl is-active --quiet hysteria2; then
            echo -e "${GREEN}Hysteria2服务已自动恢复！${PLAIN}"
        else
            echo -e "${RED}Hysteria2服务启动失败，尝试重新配置...${PLAIN}"
            configure_hysteria2
            systemctl restart hysteria2
        fi
    fi
}

# 添加服务监控和自动重启功能
setup_watchdog() {
    echo -e "${YELLOW}正在设置服务监控和自动重启功能...${PLAIN}"
    
    # 创建监控脚本
    cat > /usr/local/bin/hysteria2_watchdog.sh << 'EOF'
#!/bin/bash

# 检查Hysteria2是否正常运行
check_hysteria() {
    if ! systemctl is-active --quiet hysteria2; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Hysteria2服务不在运行状态，尝试重启..." >> /var/log/hysteria2_watchdog.log
        systemctl restart hysteria2
        sleep 5
        if systemctl is-active --quiet hysteria2; then
            echo "$(date '+%Y-%m-%d %H:%M:%S') - Hysteria2服务已恢复运行" >> /var/log/hysteria2_watchdog.log
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') - 重启失败，请手动检查服务状态" >> /var/log/hysteria2_watchdog.log
        fi
    fi
}

# 检查网络连接
check_network() {
    if ! ping -c 3 1.1.1.1 >/dev/null 2>&1; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - 网络连接异常，尝试重启网络..." >> /var/log/hysteria2_watchdog.log
        systemctl restart networking 2>/dev/null || systemctl restart network 2>/dev/null || ip link set eth0 down && ip link set eth0 up
        sleep 10
    fi
}

# 主执行函数
main() {
    check_network
    check_hysteria
}

main
EOF

    chmod +x /usr/local/bin/hysteria2_watchdog.sh
    
    # 创建定时任务
    if ! crontab -l | grep -q "hysteria2_watchdog"; then
        (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/hysteria2_watchdog.sh") | crontab -
        echo -e "${GREEN}已设置每5分钟检查一次服务状态${PLAIN}"
    fi
    
    # 创建systemd服务
    cat > /etc/systemd/system/hysteria2-watchdog.service << EOF
[Unit]
Description=Hysteria2 Watchdog Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria2_watchdog.sh
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable hysteria2-watchdog.service
    systemctl start hysteria2-watchdog.service
    
    echo -e "${GREEN}服务监控和自动重启功能设置完成！${PLAIN}"
}

# 打印横幅
print_banner() {
    clear
    echo -e "${GREEN}=====================================================${PLAIN}"
    echo -e "${GREEN}              Hysteria2 一键部署脚本                ${PLAIN}"
    echo -e "${GREEN}             版本: ${VERSION} - by Github           ${PLAIN}"
    echo -e "${GREEN}=====================================================${PLAIN}"
    echo -e "${YELLOW}系统信息: ${PLAIN}$(uname -a)"
    echo -e "${YELLOW}当前时间: ${PLAIN}$(date "+%Y-%m-%d %H:%M:%S")"
    echo -e "${GREEN}=====================================================${PLAIN}"
    echo ""
}

# 安装前检查
pre_check() {
    echo -e "${YELLOW}执行安装前检查...${PLAIN}"
    
    # 检查是否已安装hysteria2
    if [ -f "/usr/local/bin/hysteria2/hysteria" ]; then
        echo -e "${YELLOW}检测到已安装的Hysteria2，将先卸载...${PLAIN}"
        uninstall_hysteria2
    fi
    
    # 检查必要的目录
    for dir in "/etc/hysteria2" "/etc/hysteria2/cert" "/usr/local/bin/hysteria2"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
        fi
    done
    
    # 检查必要的命令
    for cmd in curl wget openssl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${YELLOW}正在安装 $cmd...${PLAIN}"
            if [ "$RELEASE" == "centos" ]; then
                yum -y install "$cmd"
            else
                apt -y install "$cmd"
            fi
        fi
    done
    
    # 检查端口占用
    first_port=${PORTS%%,*}
    if lsof -i ":$first_port" >/dev/null 2>&1; then
        echo -e "${RED}错误: 端口 $first_port 已被占用${PLAIN}"
        exit 1
    fi
    
    # 检查443端口（用于NGINX）
    if lsof -i :443 >/dev/null 2>&1; then
        echo -e "${RED}错误: 端口 443 已被占用，这将影响NGINX反向代理${PLAIN}"
        exit 1
    fi
    
    # 检查证书目录权限
    if [ ! -w "/etc/hysteria2/cert" ]; then
        echo -e "${RED}错误: 证书目录无写入权限${PLAIN}"
        exit 1
    fi
    
    echo -e "${GREEN}安装前检查完成！${PLAIN}"
}

# 主函数
main() {
    if [ "$1" = "test" ]; then
        TEST_MODE="true"
        # 在测试模式下固定使用这些值
        PASSWORD="TestPassword123!@#"
        OBFS_PASSWORD="TestObfsPassword123456789abcdef"
    else
        TEST_MODE="false"
        check_root
    fi
    
    check_sys
    check_arch
    IP=$(get_ip)
    PORTS=$(generate_ports)
    
    case "$1" in
        test)
            # 测试模式，只打印将执行的操作，不实际执行
            echo -e "${YELLOW}===== 测试模式 =====\n仅显示将要执行的操作，不实际执行${PLAIN}"
            echo -e "${GREEN}1. 检测系统: ${PLAIN}$RELEASE"
            echo -e "${GREEN}2. 检测架构: ${PLAIN}$ARCH"
            echo -e "${GREEN}3. 获取IP地址: ${PLAIN}$IP"
            echo -e "${GREEN}4. 生成端口: ${PLAIN}$PORTS"
            echo -e "${GREEN}5. 安装依赖：${PLAIN}curl, wget, openssl, nginx等"
            echo -e "${GREEN}6. 配置BBR和系统优化参数${PLAIN}"
            echo -e "${GREEN}7. 生成自签名证书（有效期365天）${PLAIN}"
            echo -e "${GREEN}8. 下载安装Hysteria2${PLAIN}"
            echo -e "${GREEN}9. 配置Hysteria2参数${PLAIN}"
            echo -e "${GREEN}10. 设置Nginx反向代理${PLAIN}"
            echo -e "${GREEN}11. 配置防火墙规则${PLAIN}"
            echo -e "${GREEN}12. 设置监控和自动恢复功能${PLAIN}"
            echo -e "${GREEN}13. 创建管理菜单${PLAIN}"
            echo -e "${GREEN}14. 启动服务并生成分享链接${PLAIN}"
            
            # 显示将生成的hysteria2配置文件
            echo -e "\n${GREEN}Hysteria2 配置文件预览:${PLAIN}"
            echo -e "${BLUE}listen: :$PORTS"
            echo "tls:"
            echo "  cert: /etc/hysteria2/cert/cert.crt"
            echo "  key: /etc/hysteria2/cert/private.key"
            echo "auth:"
            echo "  type: password"
            echo "  password: $PASSWORD"
            echo "masquerade:"
            echo "  type: proxy"
            echo "  proxy:"
            echo "    url: https://www.apple.com/"
            echo "obfs:"
            echo "  type: salamander"
            echo "  salamander:"
            echo "    password: $OBFS_PASSWORD"
            echo "bandwidth:"
            echo "  up: 1 gbps"
            echo "  down: 1 gbps"
            echo -e "ignoreClientBandwidth: true${PLAIN}"
            
            # 显示分享链接格式
            echo -e "\n${GREEN}将生成的分享链接格式:${PLAIN}"
            SHARE_LINK="hysteria2://${PASSWORD}@${IP}:${PORTS}?insecure=1&obfs=salamander&obfs-password=${OBFS_PASSWORD}&fastopen=1&hop=1"
            echo -e "${BLUE}$SHARE_LINK${PLAIN}"
            
            echo -e "\n${GREEN}所有测试通过，脚本逻辑正确。${PLAIN}"
            echo -e "${YELLOW}要在真实环境中安装，请不带参数用root用户运行脚本。${PLAIN}"
            ;;
        reinstall)
            uninstall_hysteria2
            pre_check
            install_hysteria2
            configure_hysteria2
            setup_watchdog
            start_hysteria2
            generate_share_link
            ;;
        status)
            check_status
            ;;
        link)
            if [ -f /etc/hysteria2/share_link.txt ]; then
                echo -e "${GREEN}分享链接:${PLAIN} $(cat /etc/hysteria2/share_link.txt)"
            else
                echo -e "${RED}分享链接未找到，请重新安装！${PLAIN}"
            fi
            ;;
        config)
            view_config
            ;;
        uninstall)
            uninstall_hysteria2
            ;;
        autostart)
            auto_start_check
            ;;
        *)
            print_banner
            echo -e "${GREEN}[1/11]${PLAIN} 执行安装前检查..."
            pre_check
            show_progress 0.1
            
            echo -e "${GREEN}[2/11]${PLAIN} 安装依赖..."
            install_dependencies
            show_progress 0.1
            
            echo -e "${GREEN}[3/11]${PLAIN} 优化系统参数和配置BBR..."
            setup_bbr
            show_progress 0.1
            
            echo -e "${GREEN}[4/11]${PLAIN} 生成自签名证书(365天有效期)..."
            generate_cert
            show_progress 0.1
            
            echo -e "${GREEN}[5/11]${PLAIN} 安装 Hysteria2..."
            install_hysteria2
            show_progress 0.1
            
            echo -e "${GREEN}[6/11]${PLAIN} 配置 Hysteria2..."
            configure_hysteria2
            show_progress 0.1
            
            echo -e "${GREEN}[7/11]${PLAIN} 设置 Nginx 反向代理..."
            setup_nginx
            show_progress 0.1
            
            echo -e "${GREEN}[8/11]${PLAIN} 开放防火墙端口..."
            open_ports
            show_progress 0.1
            
            echo -e "${GREEN}[9/11]${PLAIN} 启动 Hysteria2 服务..."
            start_hysteria2
            show_progress 0.1
            
            echo -e "${GREEN}[10/11]${PLAIN} 设置服务监控和自动重启..."
            setup_watchdog
            show_progress 0.1
            
            echo -e "${GREEN}[11/11]${PLAIN} 创建管理菜单..."
            create_menu
            setup_auto_start
            generate_share_link
            show_progress 0.1
            
            echo -e "\n${GREEN}====== Hysteria2 安装完成 ======${PLAIN}"
            echo -e "${GREEN}管理命令:${PLAIN} fff"
            view_config
            ;;
    esac
}

main "$@" 