#!/bin/bash
# 安全配置脚本 v4.1
# 最后更新：2025年3月21日（修订版）
#
# 本脚本对 Debian 系统进行安全加固，包括系统初始化、内核参数优化、
# SSH 安全配置、防火墙、入侵防御、用户环境、自动更新以及 Docker 的安全配置。
# 注意：请务必以 root 身份运行！

# 使用方法：提前安装screen、下载脚本、赋予执行权限、创建 screen 终端 并运行脚本
# export LC_ALL=en_US.UTF-8 && apt-get update && apt-get install -y --no-install-recommends screen curl && curl -fsSL https://raw.githubusercontent.com/hxol/cloud-backup-files/refs/heads/main/script/bash/debian_security_setup.sh -o /root/security_setup.sh && chmod +x security_setup.sh && screen -S security_setup ./security_setup.sh
# 
# 重新连接会话
# screen -r security_setup

# 检查是否为 root 用户
if [[ $EUID -ne 0 ]]; then
    echo -e "\033[31mError: Please run this script as root!\033[0m"
    exit 1
fi

# 初始化设置
set -eo pipefail
trap 'echo -e "\033[31mThe error occurred at line $LINENO，command: $BASH_COMMAND\033[0m"; exit 1' ERR

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 环境设置
export PATH=$PATH:/usr/sbin
export LC_ALL=en_US.UTF-8
export DEBIAN_FRONTEND=noninteractive
BACKUP_DIR="/root/backup_$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"

# 备份文件函数：将原文件备份到 $BACKUP_DIR 下（如果存在）
backup_file() {
    local file_path="$1"
    if [[ -f "$file_path" ]]; then
        cp -a "$file_path" "$BACKUP_DIR/$(basename "$file_path").backup_$(date +%Y%m%d%H%M%S)"
        echo -e "${YELLOW}Backed up $file_path to $BACKUP_DIR${NC}"
    fi
}

# 系统检查：检查是否为支持的 CPU 架构
check_arch() {
    arch_type=$(arch)
    if [[ "$arch_type" != "x86_64" && "$arch_type" != "aarch64" ]]; then
        echo -e "${RED}Unsupported CPU architectures: $arch_type${NC}" >&2
        exit 1
    fi
}

# 输入验证函数
validate_input() {
    validate_port() {
        [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1024 ] && [ "$1" -le 65535 ]
    }

    validate_pubkey() {
        grep -qE '^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp256) AAAA[0-9A-Za-z+/]+={0,3}( .*)?$' <<<"$1"
    }

    validate_username() {
        [[ $1 =~ ^[a-z_][a-z0-9_-]{3,31}$ ]] && ! grep -qE '^(root|bin|daemon|adm|nobody)' <<<"$1"
    }

    validate_password() {
        [[ ${#1} -ge 8 ]] && grep -qE '[A-Z]' <<<"$1" && grep -qE '[a-z]' <<<"$1" && grep -qE '[0-9]' <<<"$1"
    }

    # 执行验证
    while :; do
        read -rp "Please enter the SSH port number [1024-65535] (default 2022): " SSH_PORT
        SSH_PORT=${SSH_PORT:-2022}
        validate_port "$SSH_PORT" && break || echo -e "${RED}Invalid port number${NC}"
    done

    while :; do
        read -rp "Please paste the SSH public key content: " SSH_KEY
        validate_pubkey "$SSH_KEY" && break || echo -e "${RED}Invalid public key format${NC}"
    done

    while :; do
        read -rp "Please enter a new username: " NEW_USER
        validate_username "$NEW_USER" && break || echo -e "${RED}Invalid username${NC}"
    done

    while :; do
        read -rsp "Please enter a password (at least 8 characters, including uppercase and lowercase letters and numbers): " NEW_USER_PASS
        echo
        validate_password "$NEW_USER_PASS" && break || echo -e "${RED}The password does not meet the complexity requirements${NC}"
    done

    # 可选：是否启用密码认证（默认禁用，安全起见建议使用公钥认证）
    while :; do
        read -rp "Allow password authentication for SSH ?(y/N): " allow_pass
        case "$allow_pass" in
            [Yy]* ) PASSWORD_AUTH="yes"; break ;;
            [Nn]*|"" ) PASSWORD_AUTH="no"; break ;;
            * ) echo "Please enter y or n." ;;
        esac
    done
}

# 系统初始化
system_init() {
    echo -e "${YELLOW}[1/9] 更新系统及安装基础工具...${NC}"
    apt-get update && apt-get install -y --no-install-recommends \
        wget apt-transport-https ca-certificates \
        gnupg2 software-properties-common
}

# 配置用户环境
configure_userenv() {
    echo -e "${YELLOW}[2/9] 配置用户环境...${NC}"
    
    # 创建用户并设置密码、加入sudo组
    adduser --disabled-password --gecos "" "$NEW_USER"
    echo "$NEW_USER:$NEW_USER_PASS" | chpasswd
    usermod -aG sudo "$NEW_USER"

    # 限制谁可以使用 su
    groupadd suusers
    usermod -a -G suusers $NEW_USER
    usermod -a -G suusers root
    dpkg-statoverride --update --add root suusers 4750 /bin/su

    # 本地化设置
    apt-get install -y locales fonts-wqy-zenhei
    sed -i 's/# zh_CN.UTF-8/zh_CN.UTF-8/' /etc/locale.gen
    locale-gen
    update-locale LANG=en_US.UTF-8 LANGUAGE=en_US:zh_CN

    # 设置时区
    timedatectl set-timezone Asia/Shanghai
}

# 系统安全加固
security_hardening() {
    echo -e "${YELLOW}[3/9] 系统安全加固...${NC}"

    # 内核参数优化
    # 将内核参数写入独立配置文件，避免重复写入
    SYSCTL_CONF="/etc/sysctl.d/99-security-hardening.conf"
    backup_file /etc/sysctl.conf
    backup_file "$SYSCTL_CONF"
    cat <<EOF > "$SYSCTL_CONF"
# 网络防护
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# 连接限制
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1

# 内存防护
vm.swappiness = 10
vm.overcommit_ratio = 50

# 文件系统保护
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# 禁用IPv6路由(如果不需要)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
EOF
    sysctl -p

    # 禁用高风险服务
    systemctl mask rpcbind.service
}

# 配置SSH
configure_ssh() {
    echo -e "${YELLOW}[4/9] 配置SSH安全...${NC}"
    
    # 备份并重新生成主机密钥
    # 为避免影响现有连接，将现有主机密钥备份后再生成新密钥
    for key in /etc/ssh/ssh_host_*; do
        [[ -f "$key" ]] && backup_file "$key"
    done
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -q

    # 配置用户密钥
    mkdir -p "/home/$NEW_USER/.ssh"
    echo "$SSH_KEY" > "/home/$NEW_USER/.ssh/authorized_keys"
    chmod 700 "/home/$NEW_USER/.ssh"
    chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
    chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"

    # 写入SSH配置
    backup_file /etc/ssh/sshd_config
    cat <<EOF > /etc/ssh/sshd_config
# 基础设置
Port $SSH_PORT
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

# 密钥设置
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# 安全设置
Protocol 2
LogLevel VERBOSE
LoginGraceTime 60
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 3
MaxStartups 3:30:5

# 认证设置
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication $PASSWORD_AUTH
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# 会话设置
ClientAliveInterval 300
ClientAliveCountMax 0
X11Forwarding no
PrintMotd no

# 用户限制
AllowUsers $NEW_USER
DenyUsers root

# 加密算法
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group18-sha512

# 端口转发限制
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
EOF

# 删除短 Diffie-Hellman 模数，确保安全性
backup_file /etc/ssh/moduli

awk '$5 >= 3071' /etc/ssh/moduli | tee /etc/ssh/moduli.tmp
mv /etc/ssh/moduli.tmp /etc/ssh/moduli

    systemctl restart ssh
}

# 配置防火墙（nftables）
configure_firewall() {
    echo -e "${YELLOW}[5/9] 配置nftables防火墙...${NC}"

    apt purge -y ufw iptables
    apt-get install -y nftables
    systemctl enable nftables

    backup_file /etc/nftables.conf
    cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f
flush ruleset

define SSH_PORT = $SSH_PORT
define DOCKER_IFACE = "docker0"

table inet global {
    chain input {
        type filter hook input priority 0; policy drop;

        # 允许本地回环
        iifname "lo" accept

        # 允许已建立和相关的连接
        ct state { established, related } accept

        # 允许 SSH 访问
        tcp dport \$SSH_PORT accept

        # 允许 ICMP（ping）
        icmp type { echo-request } limit rate 5/second accept

        # 跳转到 Fail2Ban 规则
        jump f2b-sshd
    }

    chain f2b-sshd {
        # 动态规则由fail2ban管理
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct status dnat accept
        iifname \$DOCKER_IFACE oifname != \$DOCKER_IFACE accept
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table ip6 global {
    chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state { established, related } accept
        tcp dport \$SSH_PORT accept
        icmpv6 type { echo-request } limit rate 5/second accept
        jump f2b-sshd
    }
}
EOF

    nft -f /etc/nftables.conf
}

# 配置fail2ban入侵防御
configure_fail2ban() {
    echo -e "${YELLOW}[6/9] 配置入侵防御...${NC}"
    
    apt-get install -y fail2ban
    systemctl enable --now fail2ban

    cat <<EOF > /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled = true
port = $SSH_PORT
backend = systemd
logpath = %(sshd_log)s
maxretry = 3
findtime = 600
bantime = 86400
action = nftables[type=multiport]
EOF

    systemctl restart fail2ban
}

# 配置自动更新
configure_autoupdate() {
    echo -e "${YELLOW}[7/9] 配置自动更新...${NC}"
    
    apt-get install -y unattended-upgrades
    systemctl enable --now unattended-upgrades
    cat <<EOF > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=$(lsb_release -cs),label=Debian-Security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF
}

# 配置Docker
configure_docker() {
    echo -e "${YELLOW}[8/9] 配置容器安全...${NC}"
    
    # 安装Docker
    install -m 0755 -d /etc/apt/keyrings
    if ! curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc; then
        echo -e "${RED}Failed to download Docker GPG key${NC}"
        exit 1
    fi
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update && apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

    # Docker安全配置（iptables设置为true让Docker自动配置网络规则）
    mkdir -p /etc/docker
    cat <<EOF > /etc/docker/daemon.json
{
  "data-root": "/var/lib/docker",
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "3"},
  "live-restore": true,
  "icc": false,
  "userland-proxy": false,
  "iptables": false
}
EOF

    systemctl restart docker
    systemctl enable docker
}

# 最终检查
final_check() {
    echo -e "${YELLOW}[9/9] 最终验证...${NC}"
    
    # SSH配置检查
    sshd -t || { echo -e "${RED}SSH配置错误${NC}"; exit 1; }
    
    # 防火墙规则验证
    nft list ruleset >/dev/null || { echo -e "${RED}防火墙配置错误${NC}"; exit 1; }
    
    # 服务状态检查
    systemctl is-active --quiet ssh || { echo -e "${RED}SSH服务未运行${NC}"; exit 1; }
    systemctl is-active --quiet nftables || { echo -e "${RED}防火墙未运行${NC}"; exit 1; }
    fail2ban-client status sshd >/dev/null || { echo -e "${RED}fail2ban配置错误${NC}"; exit 1; }
    
    # Docker验证
    docker run --rm hello-world >/dev/null || { echo -e "${RED}Docker测试失败${NC}"; exit 1; }
}

# 主执行流程
main() {
    check_arch
    validate_input
    system_init
    configure_userenv
    security_hardening
    configure_ssh
    configure_firewall
    configure_fail2ban
    configure_autoupdate
    configure_docker
    final_check

    echo -e "\n${GREEN}安全配置完成！${NC}"
    echo -e "重要提示："
    echo -e "1. 立即测试SSH连接：${BLUE}ssh -p $SSH_PORT -i your_key $NEW_USER@$(curl -s icanhazip.com)${NC}"
    echo -e "2. 检查防火墙规则：${BLUE}nft list ruleset${NC}"
    echo -e "3. 查看fail2ban状态：${BLUE}fail2ban-client status sshd${NC}"
    echo -e "配置文件备份位于：${BLUE}$BACKUP_DIR${NC}"
}

main

echo -e "\n${GREEN}安全配置完成！${NC}\n按任意键退出…"
read -n 1
