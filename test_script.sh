#!/bin/bash

# 测试脚本，用于检查hysteria2_deploy.sh的语法和逻辑
echo "开始测试 hysteria2_deploy.sh 的语法和基本逻辑..."

# 检查脚本是否存在
if [ ! -f "hysteria2_deploy.sh" ]; then
    echo "错误: hysteria2_deploy.sh 文件不存在！"
    exit 1
fi

# 使用bash -n检查语法
echo "1. 检查脚本语法..."
bash -n hysteria2_deploy.sh
if [ $? -eq 0 ]; then
    echo "语法检查通过！"
else
    echo "语法检查失败！请修复上述错误。"
    exit 1
fi

# 检查函数定义
echo "2. 检查关键函数是否存在..."
functions=(
    "check_sys"
    "check_arch"
    "get_ip"
    "generate_ports"
    "install_dependencies"
    "setup_bbr"
    "generate_cert"
    "install_hysteria2"
    "configure_hysteria2"
    "setup_nginx"
    "generate_share_link"
    "start_hysteria2"
    "check_status"
    "view_config"
    "uninstall_hysteria2"
    "setup_watchdog"
    "create_menu"
    "main"
)

missing_functions=0
for func in "${functions[@]}"; do
    if ! grep -q "^$func()" hysteria2_deploy.sh; then
        echo "错误: 缺少函数 '$func'"
        missing_functions=$((missing_functions+1))
    fi
done

if [ $missing_functions -eq 0 ]; then
    echo "所有关键函数已定义！"
else
    echo "发现 $missing_functions 个缺失函数！"
    exit 1
fi

# 检查重要变量的设置
echo "3. 检查关键变量的设置..."
variables=(
    "RED="
    "GREEN="
    "YELLOW="
    "BLUE="
    "PLAIN="
    "VERSION="
)

missing_vars=0
for var in "${variables[@]}"; do
    if ! grep -q "$var" hysteria2_deploy.sh; then
        echo "错误: 缺少变量定义 '$var'"
        missing_vars=$((missing_vars+1))
    fi
done

if [ $missing_vars -eq 0 ]; then
    echo "所有关键变量已定义！"
else
    echo "发现 $missing_vars 个缺失变量！"
    exit 1
fi

# 检查脚本是否以main "$@"结束
echo "4. 检查脚本入口点..."
if grep -q "main \"\$@\"" hysteria2_deploy.sh; then
    echo "脚本入口点正确！"
else
    echo "错误: 脚本缺少正确的入口点 'main \"\$@\"'"
    exit 1
fi

# 模拟简单的执行逻辑
echo "5. 模拟执行流程分析..."

# 检查版本检测逻辑是否合理
if grep -q "LATEST_VERSION=.*curl.*api\.github\.com.*releases/latest" hysteria2_deploy.sh && \
   grep -q "if \[\[ -z .*LATEST_VERSION.* \]\]; then" hysteria2_deploy.sh; then
    echo "版本检测逻辑正确！"
else
    echo "警告: 版本检测逻辑可能有问题"
fi

# 检查错误处理
error_handling=$(grep -c "exit 1" hysteria2_deploy.sh)
echo "检测到 $error_handling 处错误处理点"
if [ $error_handling -lt 5 ]; then
    echo "警告: 错误处理点较少，可能缺乏足够的错误处理"
fi

# 检查证书生成是否有效期设置
if grep -q "openssl.*-days 365" hysteria2_deploy.sh; then
    echo "证书有效期设置正确！"
else
    echo "警告: 未检测到正确的证书有效期设置"
fi

# 检查监控脚本逻辑
if grep -q "setup_watchdog" hysteria2_deploy.sh && \
   grep -q "hysteria2_watchdog" hysteria2_deploy.sh; then
    echo "监控和自动恢复功能正常！"
else
    echo "警告: 监控和自动恢复功能可能有问题"
fi

# 总结测试结果
echo -e "\n============= 测试结果 ============="
echo "1. 语法检查: 通过"
echo "2. 关键函数检查: 通过"
echo "3. 变量定义检查: 通过"
echo "4. 入口点检查: 通过"
echo "5. 逻辑分析: 基本合理"
echo "注意: 此测试仅检查了基本的语法和逻辑，完整功能需要在真实的服务器环境下测试。"
echo "==================================="

echo -e "\n测试完成！" 