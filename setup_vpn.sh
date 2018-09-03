#!/bin/bash

# Please Create a user Other than root before running this script! 

# ************************************************* Settings *****************************************

# Settings to decide which protocol to install
STRONGSWAN=true
OPENCONNECT=true
SHADOWSOCKS=true
SHADOWSOCKSR=true

# Settings for system and certbot
ENABLE_ICMP=true # Server will response to ICMP(ping) request
SECURE_SSH=true # Will disable root login via ssh, make sure you have another sudo account
AUTO_UPGRADE=false # auto_upgrade will reboot system based on new updates requirement, recommand false for industry usage
SSH_PORT=22 # Used to set firewall
SSH_ACCEPT_IP="192.168.1.0/24
10.0.0.0/24" # Will only accept ssh request from this range

# Settings for STRONGSWAN
STRONGSWAN_VPN_IPPOOL="10.10.10.0/24"
STRONGSWAN_IKE="aes256gcm16-sha256-ecp521, aes256-sha256-ecp384, 3des-sha1-modp1024!" 
STRONGSWAN_ESP="aes256gcm16-sha256, aes256gcm16-ecp384, 3des-sha1-modp1024!" # iOS/Mac uses AES_GCM_16_256/PRF_HMAC_SHA2_256/ECP_521 
                                                                             # Windows 10 uses AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/ECP_384
                                                                             # Windows 7 uses 3des-sha1-modp1024

# Settings for OPENCONNECT
OC_VPN_IPPOOL="10.10.11.0/24"
OC_INSTALL_FROM_SOURCE=true
OC_VERSION="" # Specify the OpenConnect Version to Install e.g. 0.10.11, install latest if left empty
OC_PORT=443   # Same port for both UDP and TCP, default is the port for https
OC_USE_UDP=false  # Disable UDP might be helpful to fix unstable connection

# Settings for SHADOWSOCKS
LIBSODIUM_DOWNLOAD="https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"
SS_PYTHON_DOWNLOAD="https://github.com/shadowsocks/shadowsocks/archive/master.tar.gz" # Another version: "https://github.com/shadowsocks/shadowsocks/archive/2.9.1.tar.gz"
SS_PYTHON_PORT_START=20000
SS_PYTHON_PORT_END=21000
SS_PYTHON_CIPHER=aes-256-gcm # Options: aes-256-gcm, aes-192-gcm, aes-128-gcm,
                             #          aes-256-ctr, aes-192-ctr, aes-128-ctr,
                             #          aes-256-cfb, aes-192-cfb, aes-128-cfb,
                             #          camellia-128-cfb, camellia-192-cfb, camellia-256-cfb,
                             #          xchacha20-ietf-poly1305, chacha20-ietf-poly1305, chacha20-ietf, chacha20,
                             #          salsa20, rc4-md5


# Settings for SHADOWSOCKSR
SSR_DOWNLOAD="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"
SSR_PORT_START=30000
SSR_PORT_END=31000
SSR_CIPHER=aes-256-cfb # Options: aes-256-cfb, aes-192-cfb, aes-128-cfb,
                       #          aes-256-cfb8, aes-192-cfb8, aes-128-cfb8,
                       #          aes-256-ctr, aes-192-ctr, aes-128-ctr,
                       #          chacha20-ietf, chacha20, xchacha20,
                       #          salsa20, xsalsa20, rc4-md5
SSR_PROTOCOL=auth_aes128_md5 # Options: auth_chain_a, auth_chain_b, auth_chain_c, auth_chain_d, auth_chain_e, auth_chain_f,
                             #          auth_aes128_md5, auth_aes128_sha1,
                             #          auth_sha1_v4, auth_sha1_v4_compatible
                             #          verify_deflate, origin
SSR_OBFS=tls1.2_ticket_auth_compatible # Options: plain,
                                       #          http_simple, http_simple_compatible, http_post, http_post_compatible,
                                       #          tls1.2_ticket_auth, tls1.2_ticket_auth_compatible, 
                                       #          tls1.2_ticket_fastauth, tls1.2_ticket_fastauth_compatible


# ******************************************** End of Settings *********************************************

# Some Global Variables
INSTALL_VPN=false
UNINSTALL_VPN=false
SCRIPT_DIR="$(cd "$(dirname $0)"; pwd)"
LOG_DIR="${SCRIPT_DIR}/ScriptLog.log"
echo "Detailed Info Recorded in log file: $LOG_DIR" && echo "*** SYSTEM: $(uname -a)" > $LOG_DIR && echo "*** Ubuntu: $(sed 's/\\n\ \\l//g' /etc/issue)" >> $LOG_DIR  # Create Log file

# Some help functions and global settings
F_RED='\033[0;31m'
F_GRN='\033[0;32m'
F_YLW='\033[1;33m'
F_BLU='\033[0;34m'
F_WHT='\033[0m'
echo_colored(){
	echo -e "$1$2${F_WHT}"
}
echo_red(){
	echo_colored ${F_RED} "$1"
}
echo_blue(){
	echo_colored ${F_BLU} "$1"
}
echo_green(){
	echo_colored ${F_GRN} "$1"
}
echo_yellow(){
	echo_colored ${F_YLW} "$1"
}
echo_white(){
	echo_colored ${F_WHT} "$1"
}
exception(){
	echo "*** Error: $1" >> $LOG_DIR
	echo_red "Error: $1"; exit 1
}
warning(){
	echo "$1" >> $LOG_DIR
	echo_yellow "*** Warning: $1"
}
info(){
	echo "*** Info: $1" >> $LOG_DIR
	echo_green "$1"
}
info_highlight(){
	echo "*** Info: $1 $2" >> $LOG_DIR
	echo -e "${F_GRN}$1${F_YLW}$2${F_WHT}"
}
trim() {
  expand | awk 'NR == 1 {match($0, /^ */); l = RLENGTH + 1}
                {print substr($0, l)}'
} # used to trim multiline strings based on first line
apt_install() {
	for Package in $1; do apt -q=2 install -y $Package >> $LOG_DIR 2>&1 ; done
} # Install packages silently
apt_remove() {
	for Package in $1; do apt -q=2 autoremove -y $Package >> $LOG_DIR 2>&1 ; done
}
apt_install_together() {
	apt -q=2 install -y $1 >> $LOG_DIR 2>&1
}
decompress() {
	# Accept two inputs, first one should be path to compressed file, second one should be target directory
	[[ -d $2 ]] && [[ ! -n "$(find "$2" -maxdepth 0 -type d -empty 2>/dev/null)" ]] && warning "In decompression, path $2 already exist and not empty, will delete it"
	mkdir -p $2
	if [[ $1 = *.tar.gz ]]; then
		tar -zxf $1 -C $2 --strip-components=1
	elif [[ $1 = *.zip ]]; then
		rm -rf $2
		unzip $1 -d ./decompress_temp
		if [[ $(find ./decompress_temp -mindepth 1 -maxdepth 1 -type d | wc -l) = 1 ]]; then
			mv $(find ./decompress_temp -mindepth 1 -maxdepth 1 -type d) $2
		else
			mv ./decompress_temp $2
		fi
		rm -rf ./decompress_temp  
	else
		exception "Unknown file type, only support tar.gz, zip"
		exit 1
	fi
}
# End of help functions and global settings

# Parse command
POSITIONAL=()
while [[ $# -gt 0 ]]
do 
key="$1"
case $key in
	install|-i|--install)
	INSTALL_VPN=true
	shift
	;;
	uninstall|-u|--uninstall)
	UNINSTALL_VPN=true
	shift
	;;
	*)
	POSITIONAL+=("$1")
	shift
	;;
esac
done
set -- "${POSITIONAL[@]}"
if [[ -n $1 ]]; then
	warning "Unknown arguments detected: $1"
fi 
if [[ $INSTALL_VPN = false ]] && [[ $UNINSTALL_VPN = false ]]; then
	warning "Missing operation. Setting default process to installation"
	INSTALL_VPN=true
fi
# End of Parse Command

# Self Checking: Access Checking and Command Checking
info "Runing System Test..."
apt_install "language-pack-en moreutils" # Some Basic tools
[[ $(id -u) -eq 0 ]] || exception "Require sudo access, rerun as root. (e.g. sudo /path/to/this/script)" # Require sudo access
[[ -f /etc/debian_version ]] || exception "Only for Debian(Ubuntu) System" # Check System is Ubuntu
[[ $(lsb_release -rs | tr -cd '[[:digit:]]' ) -ge "1604" ]] || exception "Please use Ubuntu 16.04 or later" # Check 16.04 or later Ubuntu
[[ $INSTALL_VPN != $UNINSTALL_VPN ]] || exception "Confict Command. Specify what you want to do." # Cannot install and uninstall at same time
[[ -e /dev/net/tun ]] || exception "Network TUNnel and TAP not supported in this machine" # Tunnel availiable Checking
INTERFACE=$(ip route get 8.8.8.8 | awk -- '{printf $5}') # Get Interface related information
INTERFACE_IP=$(ifdata -pa $INTERFACE)
info "System Test...Passed"

# Installation Process
if [[ $INSTALL_VPN = true ]]; then
	[[ $STRONGSWAN = true ]] || [[ $OPENCONNECT = true ]] || [[ $SHADOWSOCKS = true ]] || [[ $SHADOWSOCKSR = true ]] || exception "No VPN selected"	
	
	# Some Basic info for later processing
	info "** Please input hostname for Let's Encrypt certificate, IP address is not allowed"
	read -p "Hostname(e.g. vpn.com): " VPN_HOSTNAME
	VPN_HOSTIP=$(dig -4 +short "$VPN_HOSTNAME")
	[[ -n "$VPN_HOSTIP" ]] || exception "Connot resolve VPN hostname"
	if [[ "$INTERFACE_IP" != "$VPN_HOSTIP" ]] ; then # Check hostIP equals to interfaceIP
		warning "$VPN_HOST resolves to HOSTIP $VPN_HOSTIP, which is not same as INTERFACE_IP $INTERFACE_IP. If set StrongSwan behind NAT, VPN might not work. "
	fi
	info "** Please input your email for Let's Encrypt Certificate, this will also be used as default admin account for VPNs **"
	read -p "Email(e.g. example@email.com): " ADMIN_EMAIL

	# Install Checking
	info "Start Installation Prerequisite Checking, this might take a long time..."
	export DEBIAN_FRONTEND=noninteractive # Update apt and set ubuntu to noninteractive mode
	apt_install "software-properties-common"
	add-apt-repository -y ppa:certbot/certbot >> $LOG_DIR 2>&1
	apt -q=2 -o Acquire::ForceIPv4=true update >> $LOG_DIR 2>&1
	apt -q=2 -y upgrade >> $LOG_DIR 2>&1
	apt_install "curl wget vim sed gawk insserv dnsutils tar xz-utils unzip"
	if [[ -f /etc/letsencrypt/cli.ini ]]; then
		warning "Old settings for Let's Encrypt detected, please be careful..."
		apt_install "iptables-persistent unattended-upgrades"
		apt -q=2 -y install certbot
	else
		apt_install "iptables-persistent unattended-upgrades certbot"
	fi
	info "Removing unused packages..."
	apt -q=2 autoremove -y >> $LOG_DIR 2>&1
	info_highlight "Network Interface: " "$INTERFACE"
	info_highlight "External IP: " "$INTERFACE_IP"
	info "Installation Prerequisite Checking...Passed"
	# End of Install Checking
	
	# Secure SSH, will restart sshd at the end of this installation
	if [[ $SECURE_SSH = true ]]; then
		info "Enhance System Security(SSH)..."
		sed -r \
		-e 's/^#?LoginGraceTime (120|2m)$/LoginGraceTime 30/' \
		-e 's/^#?PermitRootLogin yes$/PermitRootLogin no/' \
		-e 's/^#?X11Forwarding yes$/X11Forwarding no/' \
		-e 's/^#?PermitEmptyPasswords yes$/PermitEmptyPasswords no/' \
		-i.original /etc/ssh/sshd_config

		grep -Fq "MaxStartups 1" /etc/ssh/sshd_config || echo "MaxStartups 1" >> /etc/ssh/sshd_config
		grep -Fq "MaxAuthTries 2" /etc/ssh/sshd_config || echo "MaxAuthTries 2" >> /etc/ssh/sshd_config
		grep -Fq "UseDNS no" /etc/ssh/sshd_config || echo "UseDNS no" >> /etc/ssh/sshd_config
		info "System Security(SSH)...Level Up"
	fi

	# Set up auto system upgrade
	if [[ $AUTO_UPGRADE = true ]]; then
		info "Setting system auto-upgrade..."
		sed -r \
		-e 's|^//Unattended-Upgrade::MinimalSteps "true";$|Unattended-Upgrade::MinimalSteps "true";|' \
		-e 's|^//Unattended-Upgrade::Mail "root";$|Unattended-Upgrade::Mail "root";|' \
		-e 's|^//Unattended-Upgrade::Automatic-Reboot "false";$|Unattended-Upgrade::Automatic-Reboot "true";|' \
		-e 's|^//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' \
		-e 's|^//Unattended-Upgrade::Automatic-Reboot-Time "02:00";$|Unattended-Upgrade::Automatic-Reboot-Time "03:00";|' \
		-i /etc/apt/apt.conf.d/50unattended-upgrades
	
		echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/10periodic
		echo 'APT::Periodic::Download-Upgradeable-Packages "1";' >> /etc/apt/apt.conf.d/10periodic
		echo 'APT::Periodic::AutocleanInterval "7";' >> /etc/apt/apt.conf.d/10periodic
		echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/10periodic
		info "System auto-upgrade...On"
	fi

	# Configure Firewall
	info "Configure firewall for system..."
	iptables -P INPUT ACCEPT # Change policy on chain to target
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -t filter -F # Delete all existing rules
	iptables -t nat -F
	iptables -t mangle -F
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT # accept anything already accepted 
	iptables -A INPUT -i lo -j ACCEPT # accept anything on loopback interface
	iptables -A INPUT -m state --state INVALID -j DROP # Drop invalid packets
	if [[ ! $SHADOWSOCKS = true ]] && [[ ! $SHADOWSOCKSR = true ]]; then # Because shadowsocks and shadowsocksr need lots of new connections, loose this restriction
		iptables -I INPUT -i $INTERFACE -m state --state NEW -m recent --set # Set limit for repeated request from same IP
		iptables -I INPUT -i $INTERFACE -m state --state NEW -m recent --update --seconds 60 --hitcount 30 -j DROP
	fi
	if [[ $SHADOWSOCKS = true ]]; then
		info "Configure firewall rules for Shadowsocks..."
		iptables -A INPUT -p tcp -m multiport --dports $SS_PYTHON_PORT_START:$SS_PYTHON_PORT_END -j ACCEPT
		iptables -A INPUT -p udp -m multiport --dports $SS_PYTHON_PORT_START:$SS_PYTHON_PORT_END -j ACCEPT
	fi
	if [[ $SHADOWSOCKSR = true ]]; then
		info "Configure firewall rules for shadowsocks_R..."
		iptables -A INPUT -p tcp -m multiport --dports $SSR_PORT_START:$SSR_PORT_END -j ACCEPT
		iptables -A INPUT -p udp -m multiport --dports $SSR_PORT_START:$SSR_PORT_END -j ACCEPT
	fi
	if [[ $OPENCONNECT = true ]]; then
		info "Configure firewall rules for OpenConnect..."
		if [[ $OC_USE_UDP = true ]]; then
			iptables -A INPUT -p udp -m udp --dport $OC_PORT -m comment --comment "ocserv-udp" -j ACCEPT
		fi
		iptables -A INPUT -p tcp -m tcp --dport $OC_PORT -m comment --comment "ocserv-tcp" -j ACCEPT
		iptables -A FORWARD -s $OC_VPN_IPPOOL -m comment --comment "ocserv-forward-in" -j ACCEPT
		iptables -A FORWARD -d $OC_VPN_IPPOOL -m comment --comment "ocesrv-forward-out" -j ACCEPT
		iptables -t mangle -A FORWARD -s $OC_VPN_IPPOOL -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "ocserv-mangle" -j TCPMSS --clamp-mss-to-pmtu # MSS fix
		iptables -t nat -A POSTROUTING -s $OC_VPN_IPPOOL ! -d $OC_VPN_IPPOOL -m comment --comment "ocserv-postrouting" -j MASQUERADE
	fi
	if [[ $STRONGSWAN = true ]]; then
		info "Configure firewall rules for StrongSwan..."
		iptables -A INPUT -p udp -m udp --dport 500 -j ACCEPT # Accept IPSec/NAT-T for StrongSwan VPN
		iptables -A INPUT -p udp -m udp --dport 4500 -j ACCEPT
		iptables -A FORWARD --match policy --pol ipsec --dir in --proto esp -s $STRONGSWAN_VPN_IPPOOL -j ACCEPT # Forward VPN traffic anywhere
		iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d $STRONGSWAN_VPN_IPPOOL -j ACCEPT
		iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s $STRONGSWAN_VPN_IPPOOL -o $INTERFACE -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360 # Reduce MTU/MSS values for dumb VPN clients
		iptables -t nat -A POSTROUTING -s $STRONGSWAN_VPN_IPPOOL -o $INTERFACE -m policy --pol ipsec --dir out -j ACCEPT # Exempt IPsec traffic from Masquerade
		iptables -t nat -A POSTROUTING -s $STRONGSWAN_VPN_IPPOOL -o $INTERFACE -m comment --comment "strongswan-postrouting" -j MASQUERADE # Masquerade VPN traffic over interface
	fi
	echo $SSH_ACCEPT_IP |tr ' ' '\n' | while read IP_RANGE ; do iptables -A INPUT -s $IP_RANGE -p tcp -m tcp --dport $SSH_PORT -j ACCEPT ; done # Only accept ssh from certain IP rangse
	iptables -A INPUT -p tcp -m tcp --dport $SSH_PORT -j DROP # Close SSH port to void ssh attack
	if [[ $ENABLE_ICMP = true ]]; then # Enable ICMP based on settings. So we can use ping to test server
		iptables -A INPUT -d $INTERFACE_IP/32 -p icmp -m icmp --icmp-type 8 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT 
		iptables -A OUTPUT -s $INTERFACE_IP/32 -p icmp -m icmp --icmp-type 8 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
	fi
	iptables -A INPUT -j DROP # Deny all other requests
	iptables -A FORWARD -j DROP
	info "Firewall Configuration...Done"
	# End of Firewall Configure

	# Save Firewall Settings
	info "Persist Firwall Configuration..."
	debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
	debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
	dpkg-reconfigure iptables-persistent
	info "Firewall Settings Saved"

	# Configure Let's Encrypt
	info "Applying for Let's Encrypt Certificate..."
	mkdir -p /etc/letsencrypt # Configure Let's Encrypt RSA certificate
	trim << EOF > /etc/letsencrypt/cli.ini
	rsa-key-size = 4096
	pre-hook = /sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
	post-hook = /sbin/iptables -D INPUT -p tcp --dport 80 -j ACCEPT
EOF
	certbot certonly --non-interactive --agree-tos --standalone --preferred-challenges http --email $ADMIN_EMAIL -d $VPN_HOSTNAME >> $LOG_DIR 2>&1
	grep -Fq "* * * * 7 root certbot -q renew" /etc/crontab || echo "* * * * 7 root certbot -q renew" >> /etc/crontab # Set up autorenew
	info "Let's Encrypt Certificate Applied"

	# Set net, including ip_forward etc.
	info "Configure System Network and IP Forward"
	grep -Fq "net.ipv4.ip_forward = 1" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf # for VPN
	grep -Fq "net.ipv4.ip_no_pmtu_disc = 1" /etc/sysctl.conf || echo "net.ipv4.ip_no_pmtu_disc = 1" >> /etc/sysctl.conf # for UDP fragmentation
	grep -Fq "net.ipv4.conf.all.rp_filter = 1" /etc/sysctl.conf || echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf # for security
	grep -Fq "net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
	grep -Fq "net.ipv4.conf.all.send_redirects = 0" /etc/sysctl.conf || echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
	grep -Fq "net.ipv6.conf.all.disable_ipv6 = 1" /etc/sysctl.conf || echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
	grep -Fq "net.ipv6.conf.default.disable_ipv6 = 1" /etc/sysctl.conf || echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
	grep -Fq "net.ipv6.conf.lo.disable_ipv6 = 1" /etc/sysctl.conf || echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
	# If we have kernel 4.9+, we can use bbr to speed up VPN
	# grep -Fq "net.core.default_qdisc = fq" /etc/sysctl.conf || echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
	# grep -Fq "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
	sysctl -p >> $LOG_DIR 2>&1
	info "System Network Configuration...Done"

	# STRONGSWAN Installation
	if [[ $STRONGSWAN = true ]]; then
		info "Installing StrongSwan..."
		# Install StrongSwan
		apt_install "strongswan strongswan-starter libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins libstrongswan-extra-plugins" >> $LOG_DIR 2>&1 
		
		# remember to add ipsec renew after 
		grep -Eq "renew-hook.*=.*" /etc/letsencrypt/cli.ini \
		|| echo "renew-hook = " | tee --append /etc/letsencrypt/cli.ini > /dev/null \
		&& ( grep -Eq "renew-hook.*/usr/sbin/ipsec reload && /usr/sbin/ipsec secret" /etc/letsencrypt/cli.ini || sed -e '/^renew-hook.*/s_$_ \&\& /usr/sbin/ipsec reload \&\& /usr/sbin/ipsec secret_' -i /etc/letsencrypt/cli.ini ) \
		&& (sed -e 's/=\ *&&/= /' -i /etc/letsencrypt/cli.ini)

		# Set up apparmor for letsencrypt -> ipsec
		grep -Fq "letsencrypt/archive/$VPN_HOSTNAME" /etc/apparmor.d/local/usr.lib.ipsec.charon || echo "/etc/letsencrypt/archive/$VPN_HOSTNAME/* r," >> /etc/apparmor.d/local/usr.lib.ipsec.charon # Make sure this line is in apparmor
		aa-status --enabled && invoke-rc.d apparmor reload # Start apparmor	
		
		# Link certs
		info "Linking Certificates for StrongSwan..."
		ln -f -s /etc/letsencrypt/live/$VPN_HOSTNAME/cert.pem /etc/ipsec.d/certs/cert.pem
		ln -f -s /etc/letsencrypt/live/$VPN_HOSTNAME/privkey.pem /etc/ipsec.d/private/privkey.pem
		ln -f -s /etc/letsencrypt/live/$VPN_HOSTNAME/chain.pem /etc/ipsec.d/cacerts/chain.pem

		# StrongSwan Settings: ipsec.conf
		info "Prepare conf file for StrongSwan..."
		echo "config setup" > /etc/ipsec.conf
		echo "  strictcrlpolicy=yes" >> /etc/ipsec.conf	
		echo "  uniqueids=yes" >> /etc/ipsec.conf	
		echo "conn roadwarrior" >> /etc/ipsec.conf	
		echo "  auto=add" >> /etc/ipsec.conf	
		echo "  compress=no" >> /etc/ipsec.conf	
		echo "  type=tunnel" >> /etc/ipsec.conf	
		echo "  keyexchange=ikev2" >> /etc/ipsec.conf	
		echo "  fragmentation=yes" >> /etc/ipsec.conf	
		echo "  forceencaps=yes" >> /etc/ipsec.conf	
		echo "  ike=$STRONGSWAN_IKE" >> /etc/ipsec.conf	
		echo "  esp=$STRONGSWAN_ESP" >> /etc/ipsec.conf	
		echo "  dpdaction=clear" >> /etc/ipsec.conf	
		echo "  dpddelay=180s" >> /etc/ipsec.conf	
		echo "  rekey=no" >> /etc/ipsec.conf	
		echo "  left=%any" >> /etc/ipsec.conf	
		echo "  leftid=@${VPN_HOSTNAME}" >> /etc/ipsec.conf	
		echo "  leftcert=cert.pem" >> /etc/ipsec.conf	
		echo "  leftsendcert=always" >> /etc/ipsec.conf	
		echo "  leftsubnet=0.0.0.0/0" >> /etc/ipsec.conf	
		echo "  right=%any" >> /etc/ipsec.conf	
		echo "  rightid=%any" >> /etc/ipsec.conf	
		echo "  rightauth=eap-mschapv2" >> /etc/ipsec.conf	
		echo "  eap_identity=%any" >> /etc/ipsec.conf	
		echo "  rightdns=8.8.8.8, 8.8.4.4" >> /etc/ipsec.conf	
		echo "  rightsourceip=${STRONGSWAN_VPN_IPPOOL}" >> /etc/ipsec.conf	
		echo "  rightsendcert=never" >> /etc/ipsec.conf	
	
		# StrongSwan Settings: ipsec.secrets	
		echo "${VPN_HOSTNAME} : RSA \"privkey.pem\"" > /etc/ipsec.secrets
		echo "${ADMIN_EMAIL} %any : EAP \"${ADMIN_EMAIL}\"" >> /etc/ipsec.secrets

		# Restart StrongSwan. 
		ipsec restart >> $LOG_DIR 2>&1
		
		# End of StrongSwan Server Configure, Prepare for client settings
		info "Generating StrongSwan Client Settings..."
		mkdir -p ${SCRIPT_DIR}/StrongSwan_Clients/	
		info "Setting StrongSwan Script for iOS & MAC"
		trim << EOF > ${SCRIPT_DIR}/StrongSwan_Clients/StrongSwan_Client_iOS_macOS.mobileconfig
		<?xml version='1.0' encoding='UTF-8'?>
		<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
		<plist version='1.0'>
		<dict>
		  <key>PayloadContent</key>
		  <array>
		    <dict>
		      <key>IKEv2</key>
		      <dict>
		        <key>AuthenticationMethod</key>
		        <string>None</string>
		        <key>ChildSecurityAssociationParameters</key>
		        <dict>
		          <key>EncryptionAlgorithm</key>
		          <string>AES-256-GCM</string>
		          <key>IntegrityAlgorithm</key>
		          <string>SHA2-256</string>
		          <key>DiffieHellmanGroup</key>
		          <integer>21</integer>
		          <key>LifeTimeInMinutes</key>
		          <integer>1440</integer>
		        </dict>
		        <key>DeadPeerDetectionRate</key>
		        <string>Medium</string>
		        <key>DisableMOBIKE</key>
		        <integer>0</integer>
		        <key>DisableRedirect</key>
		        <integer>0</integer>
		        <key>EnableCertificateRevocationCheck</key>
		        <integer>0</integer>
		        <key>EnablePFS</key>
		        <true/>
		        <key>ExtendedAuthEnabled</key>
		        <true/>
		        <key>IKESecurityAssociationParameters</key>
		        <dict>
		          <key>EncryptionAlgorithm</key>
		          <string>AES-256-GCM</string>
		          <key>IntegrityAlgorithm</key>
		          <string>SHA2-256</string>
		          <key>DiffieHellmanGroup</key>
		          <integer>21</integer>
		          <key>LifeTimeInMinutes</key>
		          <integer>1440</integer>
		        </dict>
		        <key>LocalIdentifier</key>
		        <string>${VPN_HOSTNAME}</string>
		        <key>OnDemandEnabled</key>
		        <integer>0</integer>
		        <key>OnDemandRules</key>
		        <array>
		          <dict>
		            <key>Action</key>
		            <string>Connect</string>
		          </dict>
		        </array>
		        <key>RemoteAddress</key>
		        <string>${VPN_HOSTNAME}</string>
		        <key>RemoteIdentifier</key>
		        <string>${VPN_HOSTNAME}</string>
		        <key>UseConfigurationAttributeInternalIPSubnet</key>
		        <integer>0</integer>
		      </dict>
		      <key>IPv4</key>
		      <dict>
		        <key>OverridePrimary</key>
		        <integer>1</integer>
		      </dict>
		      <key>PayloadDescription</key>
		      <string>Configures VPN settings</string>
		      <key>PayloadDisplayName</key>
		      <string>VPN</string>
		      <key>PayloadIdentifier</key>
		      <string>com.apple.vpn.managed.$(uuidgen)</string>
		      <key>PayloadType</key>
		      <string>com.apple.vpn.managed</string>
		      <key>PayloadUUID</key>
		      <string>$(uuidgen)</string>
		      <key>PayloadVersion</key>
		      <integer>1</integer>
		      <key>Proxies</key>
		      <dict>
		        <key>HTTPEnable</key>
		        <integer>0</integer>
		        <key>HTTPSEnable</key>
		        <integer>0</integer>
		      </dict>
		      <key>UserDefinedName</key>
		      <string>${VPN_HOSTNAME}</string>
		      <key>VPNType</key>
		      <string>IKEv2</string>
		    </dict>
		  </array>
		  <key>PayloadDisplayName</key>
		  <string>IKEv2 VPN configuration (${VPN_HOSTNAME})</string>
		  <key>PayloadIdentifier</key>
		  <string>com.mackerron.vpn.$(uuidgen)</string>
		  <key>PayloadRemovalDisallowed</key>
		  <false/>
		  <key>PayloadType</key>
		  <string>Configuration</string>
		  <key>PayloadUUID</key>
		  <string>$(uuidgen)</string>
		  <key>PayloadVersion</key>
		  <integer>1</integer>
		</dict>
		</plist>
EOF
		info "Setting StrongSwan Script for Ubuntu"
		trim << EOF > ${SCRIPT_DIR}/StrongSwan_Clients/StrongSwan_Client_Ubuntu.sh
		#!/bin/bash -e
		if [[ \$(id -u) -ne 0 ]]; then echo "Please run as root (e.g. sudo ./path/to/this/script)"; exit 1; fi
		read -p "VPN username (same as entered on server): " VPNUSERNAME
		while true; do
		read -s -p "VPN password (same as entered on server): " VPNPASSWORD
		echo
		read -s -p "Confirm VPN password: " VPNPASSWORD2
		echo
		[ "\$VPNPASSWORD" = "\$VPNPASSWORD2" ] && break
		echo "Passwords didn't match -- please try again"
		done
		apt-get install -y strongswan libstrongswan-standard-plugins libcharon-extra-plugins
		apt-get install -y libcharon-standard-plugins || true  # 17.04+ only
		ln -f -s /etc/ssl/certs/DST_Root_CA_X3.pem /etc/ipsec.d/cacerts/
		grep -Fq 'jawj/IKEv2-setup' /etc/ipsec.conf || echo "
		# https://github.com/jawj/IKEv2-setup
		conn ikev2vpn
		        ikelifetime=60m
		        keylife=20m
		        rekeymargin=3m
		        keyingtries=1
		        keyexchange=ikev2
		        ike=aes256gcm16-sha256-ecp521!
		        esp=aes256gcm16-sha256!
		        leftsourceip=%config
		        leftauth=eap-mschapv2
		        eap_identity=\${VPNUSERNAME}
		        right=${VPN_HOSTNAME}
		        rightauth=pubkey
		        rightid=@${VPN_HOSTNAME}
		        rightsubnet=0.0.0.0/0
		        auto=add  # or auto=start to bring up automatically
		" >> /etc/ipsec.conf
		grep -Fq 'jawj/IKEv2-setup' /etc/ipsec.secrets || echo "
		# https://github.com/jawj/IKEv2-setup
		\${VPNUSERNAME} : EAP \"\${VPNPASSWORD}\"
		" >> /etc/ipsec.secrets
		ipsec restart
		sleep 5  # is there a better way?
		echo "Bringing up VPN ..."
		ipsec up ikev2vpn
		ipsec statusall
		echo
		echo -n "Testing IP address ... "
		VPNIP=\$(dig -4 +short ${VPN_HOSTNAME})
		ACTUALIP=\$(curl -s ifconfig.co)
		if [[ "\$VPNIP" == "\$ACTUALIP" ]]; then echo "PASSED (IP: \${VPNIP})"; else echo "FAILED (IP: \${ACTUALIP}, VPN IP: \${VPNIP})"; fi
		echo
		echo "To disconnect: ipsec down ikev2vpn"
		echo "To resconnect: ipsec up ikev2vpn"
		echo "To connect automatically: change auto=add to auto=start in /etc/ipsec.conf"
EOF
 
		info "Setting StrongSwan Script for Windows 10"
		trim << EOF > ${SCRIPT_DIR}/StrongSwan_Clients/StrongSwan_Client_Win10.ps1
		Add-VpnConnection -Name "${VPN_HOSTNAME}" -ServerAddress "${VPN_HOSTNAME}" -TunnelType IKEv2 -EncryptionLevel Maximum -AuthenticationMethod EAP
		Set-VpnConnectionIPsecConfiguration -ConnectionName "${VPN_HOSTNAME}" -AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup ECP384 -PfsGroup ECP384 -Force	
EOF
		info "StrongSwan Installation...Done"
	fi # End of StrongSwan Installation

	# OpenConnect Installation
	if [[ $OPENCONNECT = true ]]; then
		info "Installing OpenConnect..."
		
		# Install ocserv dependencies
		info "Solving OpenConnect Dependencies, this will take a while..."
		apt_install "openssl autogen automake gperf pkg-config make gcc m4 build-essential"
		apt_install "libgmp3-dev libwrap0-dev libpam0g-dev libdbus-1-dev libnl-route-3-dev libopts25-dev libnl-nf-3-dev libreadline-dev libpcl1-dev libtalloc-dev libev-dev liboath-dev nettle-dev libseccomp-dev liblz4-dev libgeoip-dev libkrb5-dev libradcli-dev libgnutls28-dev gnutls-bin protobuf-c-compiler"
		info "OpenConnect Dependencies Installed"

		
		info "Checking and downloading source package from official website"
		if [[ $OC_INSTALL_FROM_SOURCE = true ]]; then
			# Download source package from official website and compile it
			mkdir -p ${SCRIPT_DIR}/ocserv_install_temp
			Ocserv_Install=${SCRIPT_DIR}/ocserv_install_temp
			[[ $OC_VERSION = "" ]] && {
				OC_VERSION=$(curl -sL "https://ocserv.gitlab.io/www/download.html" | sed -n 's/^.*The latest released version is <b>\(.*$\)/\1/p')
				[[ $OC_VERSION = "" ]] && exception "Cannot get OpenConnect Latest Version Info from official website"
			}
			wget --quiet -c ftp://ftp.infradead.org/pub/ocserv/ocserv-$OC_VERSION.tar.xz >> $LOG_DIR 2>&1
			mv -f ${SCRIPT_DIR}/ocserv-$OC_VERSION.tar.xz $Ocserv_Install
			mkdir -p $Ocserv_Install/ocserv-$OC_VERSION
			tar -xvf $Ocserv_Install/ocserv-$OC_VERSION.tar.xz -C $Ocserv_Install >> $LOG_DIR 2>&1
			info "Configure OpenConnect from source..."
			# Switch to ocserv directory to configure files
			mkdir -p ${Ocserv_Install}/ocserv-${OC_VERSION}/build
			cd ${Ocserv_Install}/ocserv-${OC_VERSION}/build
			../configure --prefix=/usr --sysconfdir=/etc >> $LOG_DIR 2>&1
			info "Install OpenConnect..."
			make >> $LOG_DIR 2>&1
			make install >> $LOG_DIR 2>&1
			cd ${SCRIPT_DIR}
			# Switch back and test installation
			[[ -f /usr/sbin/ocserv ]] || exception "Ocserv install failure, check log for details" # Check install result
			info "OpenConnect Installed"
		else
			# Install OpenConnect from apt repository, this version might not the latest one
			info "Install OpenConnect"
			if [[ $OC_VERSION = "" ]]; then
				apt_install "ocserv"
			else
				info "make sure you select existing ocserv version..."
				apt policy ocserv
				read -p "Give me your choice: " OC_VERSION
				apt -q=2 install -y ocserv=$OC_VERSION >> $LOG_DIR 2>&1
			fi
			info "OpenConnect Installed through apt"
			#exception "Please install OpenConnect through source...This part is not tested yet"
		fi					
		
		# Link certs
		info "Linking Certificates for OpenConnect..."
		mkdir -p /etc/ocserv/certs
		ln -f -s /etc/letsencrypt/live/$VPN_HOSTNAME/cert.pem /etc/ocserv/certs/cert.pem
		ln -f -s /etc/letsencrypt/live/$VPN_HOSTNAME/privkey.pem /etc/ocserv/certs/privkey.pem
		ln -f -s /etc/letsencrypt/live/$VPN_HOSTNAME/fullchain.pem /etc/ocserv/certs/fullchain.pem

		# Start to configure OpenConnect with PAM
		info "Configuring OpenConnect..."
		mkdir -p ${SCRIPT_DIR}/ocserv_install_temp/config_ocserv_temp
		trim << EOF > ${SCRIPT_DIR}/ocserv_install_temp/config_ocserv_temp/ocserv
			#!/bin/sh
			### BEGIN INIT INFO
			# Provides:          ocserv
			# Required-Start:    \$network \$remote_fs \$syslog
			# Required-Stop:     \$network \$remote_fs \$syslog
			# Default-Start:     2 3 4 5
			# Default-Stop:      0 1 6
			# Short-Description: ocserv
			# Description:       OpenConnect VPN server compatible with
			#                    Cisco AnyConnect VPN.
			### END INIT INFO

			# Author: liyangyijie <liyangyijie@gmail.com>

			# PATH should only include /usr/ if it runs after the mountnfs.sh script
			PATH=/sbin:/usr/sbin:/bin:/usr/bin
			DESC=ocserv
			NAME=ocserv
			DAEMON=/usr/sbin/ocserv
			DAEMON_ARGS=""
			CONFFILE="/etc/ocserv/ocserv.conf"
			PIDFILE=/var/run/\$NAME/\$NAME.pid
			SCRIPTNAME=/etc/init.d/\$NAME

			# Exit if the package is not installed
			[ -x \$DAEMON ] || exit 0

			: \${USER:="root"}
			: \${GROUP:="root"}

			# Load the VERBOSE setting and other rcS variables
			. /lib/init/vars.sh

			# Define LSB log_* functions.
			# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
			. /lib/lsb/init-functions

			# Show details
			VERBOSE="yes"

			#
			# Function that starts the daemon/service
			#
			do_start()
			{
			    # Take care of pidfile permissions
			    mkdir /var/run/\$NAME 2>/dev/null || true
			    chown "\$USER:\$GROUP" /var/run/\$NAME

			    # Return
			    #   0 if daemon has been started
			    #   1 if daemon was already running
			    #   2 if daemon could not be started
			    start-stop-daemon --start --quiet --pidfile \$PIDFILE --chuid \$USER:\$GROUP --exec \$DAEMON --test > /dev/null \
			        || return 1
			    start-stop-daemon --start --quiet --pidfile \$PIDFILE --chuid \$USER:\$GROUP --exec \$DAEMON -- \
			        -c "\$CONFFILE" \$DAEMON_ARGS \
			        || return 2
			}

			#
			# Function that stops the daemon/service
			#
			do_stop()
			{
			    # Return
			    #   0 if daemon has been stopped
			    #   1 if daemon was already stopped
			    #   2 if daemon could not be stopped
			    #   other if a failure occurred
			    start-stop-daemon --stop --quiet --retry=KILL/5 --pidfile \$PIDFILE --exec \$DAEMON
			    RETVAL="\$?"
			    [ "\$RETVAL" = 2 ] && return 2
			    # Wait for children to finish too if this is a daemon that forks
			    # and if the daemon is only ever run from this initscript.
			    # If the above conditions are not satisfied then add some other code
			    # that waits for the process to drop all resources that could be
			    # needed by services started subsequently.  A last resort is to
			    # sleep for some time.
			    start-stop-daemon --stop --quiet --oknodo --retry=KILL/5 --exec \$DAEMON
			    [ "\$?" = 2 ] && return 2
			    # Many daemons don't delete their pidfiles when they exit.
			    rm -f \$PIDFILE
			    return "\$RETVAL"
			}

			case "\$1" in
			    start)
			        [ "\$VERBOSE" != no ] && log_daemon_msg "Starting \$DESC " "\$NAME"
			        do_start
			        case "\$?" in
			            0|1) [ "\$VERBOSE" != no ] && log_end_msg 0 ;;
			            2) [ "\$VERBOSE" != no ] && log_end_msg 1 ;;
			        esac
			    ;;
			    stop)
			    [ "\$VERBOSE" != no ] && log_daemon_msg "Stopping \$DESC" "\$NAME"
			    do_stop
			    case "\$?" in
			        0|1) [ "\$VERBOSE" != no ] && log_end_msg 0 ;;
			        2) [ "\$VERBOSE" != no ] && log_end_msg 1 ;;
			    esac
			    ;;
			    debug)
			        DAEMON_ARGS="-f -d 2"
			        [ "\$2" != "" ] && DAEMON_ARGS="-f -d \$2"
			        [ "\$VERBOSE" != no ] && log_daemon_msg "Starting \$DESC " "\$NAME"
			        do_start
			        case "\$?" in
			            0|1) [ "\$VERBOSE" != no ] && log_end_msg 0 ;;
			            2) [ "\$VERBOSE" != no ] && log_end_msg 1 ;;
			        esac
			    ;;
			    status)
			        status_of_proc "\$DAEMON" "\$NAME" && exit 0 || exit \$?
			    ;;
			    restart|force-reload)
			        log_daemon_msg "Restarting \$DESC" "\$NAME"
			        do_stop
			        case "\$?" in
			            0|1)
			                do_start
			                case "\$?" in
			                    0) log_end_msg 0 ;;
			                    1) log_end_msg 1 ;; # Old process is still running
			                    *) log_end_msg 1 ;; # Failed to start
			                esac
			            ;;
			            *)
			            # Failed to stop
			            log_end_msg 1
			            ;;
			        esac
			    ;;
			    *)
			    echo "Usage: \$SCRIPTNAME {start|stop|status|restart|force-reload|debug}" >&2
			    exit 3
			    ;;
			esac
			:
EOF
		trim << EOF > ${SCRIPT_DIR}/ocserv_install_temp/config_ocserv_temp/ocserv.conf
		auth = "plain[passwd=/etc/ocserv/ocpasswd]"
		server-cert = /etc/ocserv/certs/fullchain.pem
		server-key = /etc/ocserv/certs/privkey.pem
		dh-params = /etc/ocserv/certs/dh.pem
		default-domain = ${VPN_HOSTNAME}

		tcp-port = 443
		udp-port = 443
		ipv4-network = 10.10.11.0
		ipv4-netmask = 255.255.255.0
		dns = 8.8.8.8
		dns = 8.8.4.4

		run-as-user = nobody
		run-as-group = nogroup
		socket-file = /var/run/ocserv-socket

		isolate-workers = false
		max-clients = 256
		max-same-clients = 1

		mtu = 1200
		keepalive = 32400
		dpd = 180
		mobile-dpd = 1800
		try-mtu-discovery = true
		compression = true
		tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
		auth-timeout = 60
		idle-timeout = 1200
		mobile-idle-timeout = 1200
		max-ban-score = 50
		ban-reset-time = 300
		cookie-timeout = 86400
		deny-roaming = false
		rekey-time = 172800
		rekey-method = ssl
		use-utmp = true
		use-occtl = true
		pid-file = /var/run/ocserv.pid
		device = vpns
		predictable-ips = true
		ping-leases = false
		cisco-client-compat = true
EOF
		certtool --generate-dh-params --sec-param medium --outfile ${SCRIPT_DIR}/ocserv_install_temp/config_ocserv_temp/dh.pem >> $LOG_DIR 2>&1
		# Move and apply these config files
		[[ -f /etc/ocserv/ocserv.conf ]] && mv /etc/ocserv/ocserv.conf /etc/ocserv/ocserv.conf.bak >> $LOG_DIR 2>&1
		cp ${SCRIPT_DIR}/ocserv_install_temp/config_ocserv_temp/ocserv.conf /etc/ocserv/ocserv.conf >> $LOG_DIR 2>&1
		cp ${SCRIPT_DIR}/ocserv_install_temp/config_ocserv_temp/dh.pem /etc/ocserv/certs/dh.pem >> $LOG_DIR 2>&1
		cp ${SCRIPT_DIR}/ocserv_install_temp/config_ocserv_temp/ocserv /etc/init.d/ocserv >> $LOG_DIR 2>&1
		chmod 755 /etc/init.d/ocserv
		systemctl daemon-reload >> $LOG_DIR 2>&1
		# Bootup with system
		systemctl enable ocserv >> $LOG_DIR 2>&1 || insserv ocserv >> $LOG_DIR 2>&1 
		# Edit Conf file based on settings. 
			# Disable UDP if OC_USE_UDP is set to other values
			[[ ! $OC_USE_UDP = true ]] && sed -i 's|^[ \t]*\(udp-port = \)|# \1|' /etc/ocserv/ocserv.conf >> $LOG_DIR 2>&1
		# Add User to server
		echo "${ADMIN_EMAIL} ${ADMIN_EMAIL}"| tr " " "\n" | ocpasswd -c /etc/ocserv/ocpasswd ${ADMIN_EMAIL}
		info "OpenConnect Configuration...Done"
		
		# Set up auto restart for updated certificate
		grep -Eq "renew-hook.*=.*" /etc/letsencrypt/cli.ini \
		|| echo "renew-hook = " | tee --append /etc/letsencrypt/cli.ini > /dev/null \
		&& ( grep -Eq "renew-hook.*/etc/init.d/ocserv restart" /etc/letsencrypt/cli.ini || sed -e '/^renew-hook.*/s_$_ \&\& /etc/init.d/ocserv restart_' -i /etc/letsencrypt/cli.ini ) \
		&& (sed -e 's/=\ *&&/= /' -i /etc/letsencrypt/cli.ini)

		info "Retart OpenConnect..."
		/etc/init.d/ocserv stop >> $LOG_DIR 2>&1
		# Force stop if ocserv is still running
		Oc_pid=$(pidof ocserv)
		if [[ ! -z $Oc_pid ]]; then
			for Pid in $Oc_pid
			do
				kill -9 $Pid >> $LOG_DIR 2>&1
				if [[ $? -eq 0 ]]; then
					info "Killed running ocserv..."
				else
					warning "Cannot kill running ocserv..."
				fi
			done
		fi
		/etc/init.d/ocserv start >> $LOG_DIR 2>&1
		info "OpenConnect restart...Done"

		info "Clean OpenConnect Installation..."
		rm -rf ${SCRIPT_DIR}/ocserv_install_temp

		info "OpenConnect Installation...Done"
	fi # End of OpenConnect Installation
	
	# Shadowsocks-Python Installation
	if [[ $SHADOWSOCKS = true ]]; then
		# Install some necessary packages
		mkdir -p /etc/shadowsocks_python >> $LOG_DIR 2>&1
		apt_install "python python-dev openssl libssl-dev gcc automake autoconf make libtool"
		# Install pip and setuptools if they not ready
		wget --no-check-certificate -O ${SCRIPT_DIR}/get-pip.py https://bootstrap.pypa.io/get-pip.py >> $LOG_DIR 2>&1
		python ${SCRIPT_DIR}/get-pip.py >> $LOG_DIR 2>&1
		rm -rf ${SCRIPT_DIR}/get-pip.py
		
		# Install libsodium
		info "Installing libsodium..."
		# Download libsodium first
		info "   Downloading libsodium..."
		Libsodium_filename="$(basename ${LIBSODIUM_DOWNLOAD})"
		if ! wget --no-check-certificate -O ${SCRIPT_DIR}/${Libsodium_filename} ${LIBSODIUM_DOWNLOAD} >> $LOG_DIR 2>&1; then
			exception "   Cannot download libsodium for shadowsocks"
		fi
		info "   Done"
		if [[ ! -f /usr/lib/libsodium.a ]]; then
			decompress ${SCRIPT_DIR}/${Libsodium_filename} ${SCRIPT_DIR}/libsodium_install_temp >> $LOG_DIR 2>&1
			mkdir -p ${SCRIPT_DIR}/libsodium_install_temp/build >> $LOG_DIR 2>&1
			cd ${SCRIPT_DIR}/libsodium_install_temp/build
			../configure --prefix=/usr && make && make install >> $LOG_DIR 2>&1
			if [[ $? -ne 0 ]]; then
				cd ${SCRIPT_DIR}
				rm -rf ${SCRIPT_DIR}/${Libsodium_filename} ${SCRIPT_DIR}/libsodium_install_temp
				exception "libsodium install failed"
			fi
		fi
		cd ${SCRIPT_DIR}
		rm -rf ${SCRIPT_DIR}/libsodium_install_temp ${SCRIPT_DIR}/${Libsodium_filename}
		ldconfig >> $LOG_DIR 2>&1
		info "Libsodium Installation...Done"

		# Install Shadowsocks
		info "Installing Shadowsocks_python..."
			# Download Shadowsocks-python first
			info "   Downloading Shadowsocks-python..."
			Ss_filename="$(basename ${SS_PYTHON_DOWNLOAD})"
			if ! wget --no-check-certificate -O ${SCRIPT_DIR}/${Ss_filename} ${SS_PYTHON_DOWNLOAD} >> $LOG_DIR 2>&1; then
				exception "   Cannot download shadowsocks"
			fi
			info "   Done"
		decompress ${SCRIPT_DIR}/${Ss_filename} ${SCRIPT_DIR}/ss_install_temp >> $LOG_DIR 2>&1
		Ss_dir=${SCRIPT_DIR}/ss_install_temp # $(find ${SCRIPT_DIR}/ss_install_temp -maxdepth 1 -mindepth 1 -type d) # There is one more layer for ss source files
		cd $Ss_dir
		python setup.py install --record /etc/shadowsocks_python/shadowsocks_install.log >> $LOG_DIR 2>&1
		if [[ -f /usr/bin/ssserver ]] || [[ -f /usr/local/bin/ssserver ]]; then
			cd ${SCRIPT_DIR}
			rm -rf ${SCRIPT_DIR}/${Ss_filename} ${SCRIPT_DIR}/ss_install_temp
			info "Shadowsocks-python Installation...Done"
		else
			cd ${SCRIPT_DIR}
			rm -rf ${SCRIPT_DIR}/${Ss_filename} ${SCRIPT_DIR}/ss_install_temp
			exception "Shadowsocks-python install failed"
		fi
		# End of Shadowsocks Installation

		# Add script for auto-start
		trim << EOF > /etc/init.d/shadowsocks_python
		#!/bin/bash

		### BEGIN INIT INFO
		# Provides:          Shadowsocks
		# Required-Start:    \$network \$local_fs \$remote_fs
		# Required-Stop:     \$network \$local_fs \$remote_fs
		# Default-Start:     2 3 4 5
		# Default-Stop:      0 1 6
		# Short-Description: Fast tunnel proxy that helps you bypass firewalls
		# Description:       Start or stop the Shadowsocks server
		### END INIT INFO

		# Author: Teddysun <i@teddysun.com>

		NAME=Shadowsocks
		if [ -f /usr/bin/ssserver ]; then
		    DAEMON=/usr/bin/ssserver
		elif [ -f /usr/local/bin/ssserver ]; then
		    DAEMON=/usr/local/bin/ssserver
		fi
		if [ -f /etc/shadowsocks_python/config.json ]; then
		    CONF=/etc/shadowsocks_python/config.json
		elif [ -f /etc/shadowsocks_python.json ]; then
		    CONF=/etc/shadowsocks_python.json
		fi
		RETVAL=0

		check_running(){
		    PID=\$(ps -ef | grep -v grep | grep -i "\${DAEMON}" | awk '{print \$2}')
		    if [ -n "\$PID" ]; then
		        return 0
		    else
		        return 1
		    fi
		}

		do_start(){
		    check_running
		    if [ \$? -eq 0 ]; then
		        echo "\$NAME (pid \$PID) is already running..."
		        exit 0
		    else
		        \$DAEMON -c \$CONF -d start
		        RETVAL=\$?
		        if [ \$RETVAL -eq 0 ]; then
		            echo "Starting \$NAME success"
		        else
		            echo "Starting \$NAME failed"
		        fi
		    fi
		}

		do_stop(){
		    check_running
		    if [ \$? -eq 0 ]; then
		        \$DAEMON -c \$CONF -d stop
		        RETVAL=\$?
		        if [ \$RETVAL -eq 0 ]; then
		            echo "Stopping \$NAME success"
		        else
		            echo "Stopping \$NAME failed"
		        fi
		    else
		        echo "\$NAME is stopped"
		        RETVAL=1
		    fi
		}

		do_status(){
		    check_running
		    if [ \$? -eq 0 ]; then
		        echo "\$NAME (pid \$PID) is running..."
		    else
		        echo "\$NAME is stopped"
		        RETVAL=1
		    fi
		}

		do_restart(){
		    do_stop
		    sleep 0.5
		    do_start
		}

		case "\$1" in
		    start|stop|restart|status)
		    do_\$1
		    ;;
		    *)
		    echo "Usage: \$0 { start | stop | restart | status }"
		    RETVAL=1
		    ;;
		esac

		exit \$RETVAL
EOF
		chmod 755 /etc/init.d/shadowsocks_python
		update-rc.d -f shadowsocks_python defaults >> $LOG_DIR 2>&1

		# Config shadowsocks 
		SS_PYTHON_CONFIGFILE=/etc/shadowsocks_python/config.json
		trim << EOF > $SS_PYTHON_CONFIGFILE
		{
		    "server":"0.0.0.0",
		    "local_address":"127.0.0.1",
		    "local_port":1080,
		    "port_password":{
		    	"${SS_PYTHON_PORT_START}":"${ADMIN_EMAIL}"
		    },
		    "timeout":300,
		    "method":"${SS_PYTHON_CIPHER}",
		    "fast_open":false
		}
EOF

		# restart shadowsocks
		info "Starting Shadowsocks..."
		/etc/init.d/shadowsocks_python restart >> $LOG_DIR 2>&1
	fi # End of Shadowsocks Installation

	# SHADOWSOCKS_R Installation 
	if [[ $SHADOWSOCKSR = true ]]; then
		# Pre-install and install some packages
		mkdir -p /etc/shadowsocks_r
		apt_install "python python-dev python-setuptools openssl automake autoconf make libtool"

		# Install libsodium
		info "Installing libsodium..."
		# Download libsodium first
		info "   Downloading libsodium..."
		Libsodium_filename="$(basename ${LIBSODIUM_DOWNLOAD})"
		if ! wget --no-check-certificate -O ${SCRIPT_DIR}/${Libsodium_filename} ${LIBSODIUM_DOWNLOAD} >> $LOG_DIR 2>&1; then
			exception "   Cannot download libsodium for shadowsocks"
		fi
		info "   Done"
		if [[ ! -f /usr/lib/libsodium.a ]]; then
			decompress ${SCRIPT_DIR}/${Libsodium_filename} ${SCRIPT_DIR}/libsodium_install_temp >> $LOG_DIR 2>&1
			mkdir -p ${SCRIPT_DIR}/libsodium_install_temp/build
			cd ${SCRIPT_DIR}/libsodium_install_temp/build
			../configure --prefix=/usr && make && make install >> $LOG_DIR 2>&1
			if [[ $? -ne 0 ]]; then
				cd ${SCRIPT_DIR}
				rm -rf ${SCRIPT_DIR}/${Libsodium_filename} ${SCRIPT_DIR}/libsodium_install_temp
				exception "libsodium install failed"
			fi
		fi
		cd ${SCRIPT_DIR}
		rm -rf ${SCRIPT_DIR}/libsodium_install_temp ${SCRIPT_DIR}/${Libsodium_filename}
		ldconfig >> $LOG_DIR 2>&1
		info "Libsodium Installation...Done"

		# Install ShadowsocksR
		info "Installing ShadowsocksR..."
			# Download ShadowsocksR first
			info "   Downloading ShadowsocksR..."
			Ssr_filename="$(basename ${SSR_DOWNLOAD})"
			if ! wget --no-check-certificate -O ${SCRIPT_DIR}/${Ssr_filename} ${SSR_DOWNLOAD} >> $LOG_DIR 2>&1; then
				exception "   Cannot download shadowsocksr"
			fi
			info "   Done"
		decompress ${SCRIPT_DIR}/${Ssr_filename} ${SCRIPT_DIR}/ssr_install_temp >> $LOG_DIR 2>&1
		Ssr_dir=${SCRIPT_DIR}/ssr_install_temp
		mkdir -p /usr/bin/shadowsocks_r
		cp -r ${Ssr_dir}/shadowsocks /usr/bin/shadowsocks_r/shadowsocks  >> $LOG_DIR 2>&1 # Be careful, server.py must under directory "shadowsocks"
		if [[ ! -f /usr/bin/shadowsocks_r/shadowsocks/server.py ]]; then
			rm -rf ${SCRIPT_DIR}/ssr_install_temp
			rm -rf ${SCRIPT_DIR}/${Ssr_filename}
			exception "Shadowsocks_R Installation failed"
		else
			rm -rf ${SCRIPT_DIR}/ssr_install_temp
			rm -rf ${SCRIPT_DIR}/${Ssr_filename}
			info "Shadowsocks_R Installation...Done"
		fi

		# Config Auto start
		trim << EOF > /etc/init.d/shadowsocks_r
		#!/bin/bash

		### BEGIN INIT INFO
		# Provides:          ShadowsocksR
		# Required-Start:    \$network \$local_fs \$remote_fs
		# Required-Stop:     \$network \$local_fs \$remote_fs
		# Default-Start:     2 3 4 5
		# Default-Stop:      0 1 6
		# Short-Description: Fast tunnel proxy that helps you bypass firewalls
		# Description:       Start or stop the ShadowsocksR server
		### END INIT INFO

		# Author: Teddysun <i@teddysun.com>

		NAME=ShadowsocksR
		DAEMON=/usr/bin/shadowsocks_r/shadowsocks/server.py
		if [ -f /etc/shadowsocks_r/config.json ]; then
		    CONF=/etc/shadowsocks_r/config.json
		elif [ -f /etc/shadowsocks_r.json ]; then
		    CONF=/etc/shadowsocks_r.json
		fi
		RETVAL=0

		check_running(){
		    PID=\$(ps -ef | grep -v grep | grep -i "\${DAEMON}" | awk '{print \$2}')
		    if [ -n "\$PID" ]; then
		        return 0
		    else
		        return 1
		    fi
		}
		do_start(){
		    check_running
		    if [ \$? -eq 0 ]; then
		        echo "\$NAME (pid \$PID) is already running..."
		        exit 0
		    else
		        \$DAEMON -c \$CONF -d start
		        RETVAL=\$?
		        if [ \$RETVAL -eq 0 ]; then
		            echo "Starting \$NAME success"
		        else
		            echo "Starting \$NAME failed"
		        fi
		    fi
		}
		do_stop(){
		    check_running
		    if [ \$? -eq 0 ]; then
		        \$DAEMON -c \$CONF -d stop
		        RETVAL=\$?
		        if [ \$RETVAL -eq 0 ]; then
		            echo "Stopping \$NAME success"
		        else
		            echo "Stopping \$NAME failed"
		        fi
		    else
		        echo "\$NAME is stopped"
		        RETVAL=1
		    fi
		}
		do_status(){
		    check_running
		    if [ \$? -eq 0 ]; then
		        echo "\$NAME (pid \$PID) is running..."
		    else
		        echo "\$NAME is stopped"
		        RETVAL=1
		    fi
		}
		do_restart(){
		    do_stop
		    sleep 0.5
		    do_start
		}
		case "\$1" in
		    start|stop|restart|status)
		    do_\$1
		    ;;
		    *)
		    echo "Usage: \$0 { start | stop | restart | status }"
		    RETVAL=1
		    ;;
		esac
		exit \$RETVAL
EOF
		chmod 755 /etc/init.d/shadowsocks_r
		update-rc.d -f shadowsocks_r defaults >> $LOG_DIR 2>&1

		# Config shadowsocks_r
		SSR_CONFIGFILE=/etc/shadowsocks_r/config.json
		trim << EOF > $SSR_CONFIGFILE
		{
		    "server":"0.0.0.0",
		    "server_ipv6":"[::]",
		    "local_address":"127.0.0.1",
		    "local_port":1080,
		    "port_password":{
		    	"${SSR_PORT_START}":"${ADMIN_EMAIL}"
		    },
		    "timeout":120,
		    "method":"${SSR_CIPHER}",
		    "protocol":"${SSR_PROTOCOL}",
		    "protocol_param":"",
		    "obfs":"${SSR_OBFS}",
		    "obfs_param":"",
		    "redirect":"",
		    "dns_ipv6":false,
		    "fast_open":false,
		    "workers":1
		}
EOF
		/etc/init.d/shadowsocks_r restart >> $LOG_DIR 2>&1

		# Clean Installation
		rm -rf ${SCRIPT_DIR}/ssr_install_temp
	fi # End of SHADOWSOCKS_R Installation

	# Generate command for user operation
	if [[ $SHADOWSOCKS = true ]]; then
		trim << EOF > /usr/bin/ss_vpnuser
		import sys
		import json
				
		CONFIG_FILEPATH="${SS_PYTHON_CONFIGFILE}"
		PROGRAM_NAME="shadowsocks-python"
		START_PORT=${SS_PYTHON_PORT_START}
		END_PORT=${SS_PYTHON_PORT_END}

		def main(operation, password):
			def write_to_json(obj, json_filepath="./none.json"):
				with open(json_filepath, "w") as f:
					json.dump(obj, f, sort_keys=True, indent=4, separators=(',', ':'))
					
			def read_from_json(json_filepath="./none.json"):
				with open(json_filepath,"r") as f:
					temp_data = json.load(f)
				return temp_data
				
			config_file=read_from_json(json_filepath=CONFIG_FILEPATH)
			if operation in ["add", "adduser", "--adduser", "--add", "-a"]:
				password_dict={pwd:prt for (prt, pwd) in config_file["port_password"].items()}
				# if password already exist, output relative information and exit
				if str(password) in password_dict:
					print("user exist in "+str(PROGRAM_NAME))
					print("user port: "+str(password_dict[str(password)]))
					print("user password: "+str(password))
					return
				# If password don't exist, assign a unused port to it
				for i in range(min(START_PORT, END_PORT), max(START_PORT, END_PORT)+1, 1):
					if str(i) in config_file["port_password"]:
						continue
					else:
						config_file["port_password"][str(i)]=password
						print("user added to "+str(PROGRAM_NAME))
						print("user port: "+str(i))
						print("user password: "+str(password))
						break
			elif operation in ["del", "delete", "deluser", "--deluser", "--delete", "-d"]:
				for key in config_file["port_password"]:
					if config_file["port_password"][key] == password:
						del config_file["port_password"][key]
						print("Delete user <"+str(password)+"> from "+str(PROGRAM_NAME))
						break
			write_to_json(config_file, CONFIG_FILEPATH)
				
		if __name__ == "__main__":
			if len(sys.argv) > 2:
				main(sys.argv[1], sys.argv[2])
			else:
				raise ValueError("Incorrect input arguments")
EOF
	fi
	if [[ $SHADOWSOCKSR = true ]]; then
		trim << EOF > /usr/bin/ssr_vpnuser
		import sys
		import json
				
		CONFIG_FILEPATH="${SSR_CONFIGFILE}"
		PROGRAM_NAME="shadowsocks-R"
		START_PORT=${SSR_PORT_START}
		END_PORT=${SSR_PORT_END}

		def main(operation, password):
			def write_to_json(obj, json_filepath="./none.json"):
				with open(json_filepath, "w") as f:
					json.dump(obj, f, sort_keys=True, indent=4, separators=(',', ':'))
					
			def read_from_json(json_filepath="./none.json"):
				with open(json_filepath,"r") as f:
					temp_data = json.load(f)
				return temp_data
				
			config_file=read_from_json(json_filepath=CONFIG_FILEPATH)
			if operation in ["add", "adduser", "--adduser", "--add", "-a"]:
				password_dict={pwd:prt for (prt, pwd) in config_file["port_password"].items()}
				# if password already exist, output relative information and exit
				if str(password) in password_dict:
					print("user exist in "+str(PROGRAM_NAME))
					print("user port: "+str(password_dict[str(password)]))
					print("user password: "+str(password))
					return
				# If password don't exist, assign a unused port to it
				for i in range(min(START_PORT, END_PORT), max(START_PORT, END_PORT)+1, 1):
					if str(i) in config_file["port_password"]:
						continue
					else:
						config_file["port_password"][str(i)]=password
						print("user added to "+str(PROGRAM_NAME))
						print("user port: "+str(i))
						print("user password: "+str(password))
						break
			elif operation in ["del", "delete", "deluser", "--deluser", "--delete", "-d"]:
				for key in config_file["port_password"]:
					if config_file["port_password"][key] == password:
						del config_file["port_password"][key]
						print("Delete user <"+str(password)+"> from "+str(PROGRAM_NAME))
						break
			write_to_json(config_file, CONFIG_FILEPATH)
				
		if __name__ == "__main__":
			if len(sys.argv) > 2:
				main(sys.argv[1], sys.argv[2])
			else:
				raise ValueError("Incorrect input arguments")
EOF
	fi
	trim << EOF > /usr/sbin/vpnuser
	#!/bin/bash

	STRONGSWAN=$STRONGSWAN
	OPENCONNECT=$OPENCONNECT
	SHADOWSOCKS=$SHADOWSOCKS
	SHADOWSOCKSR=$SHADOWSOCKSR
	
	STRONGSWAN_USER_LIST=/etc/ipsec.secrets
	OPENCONNECT_USER_LIST=/etc/ocserv/ocpasswd
	GENERAL_USER_LIST=/etc/vpnuser

	exception(){
		echo "Error: \$1"; exit 1
	}
	warning(){
		echo "*** Warning: \$1"
	}
	info(){
		echo "\$1"
	}
	trim() {
	  expand | awk 'NR == 1 {match(\$0, /^ */); l = RLENGTH + 1}
	                {print substr(\$0, l)}'
	} # used to trim multiline strings based on first line
	show_help(){
		trim << EOF_END

	Usage: \${0##*/} [-a USERNAME PASSWORD] [-d USERNAME]

	Operate VPNs Users based on installation (StrongSwan, OpenConnect, Shadowsocks, ShadowsocksR), require sudo access

		-a, --adduser, adduser        add new user to all VPNs, require USERNAME and PASSWORD. Can be used to change password
		-d, --deluser, deluser        delete user from VPNs

	EOF_END
	}

	[[ \$(id -u) -eq 0 ]] || ( show_help; exception "Require sudo access, rerun as sudo user." ) # Require sudo access
	[[ -f \$GENERAL_USER_LIST ]] || ( warning "General user list missing, create an empty one"; touch \$GENERAL_USER_LIST; chmod 700 \$GENERAL_USER_LIST )  

	# main body to process request
	restart_vpns() {
		if [[ \$STRONGSWAN = true ]]; then
			info "Restart Strongswan..."
			ipsec restart 
		fi
		if [[ \$OPENCONNECT = true ]]; then
			info "Restart OpenConnect..."
			/etc/init.d/ocserv restart
		fi
		if [[ \$SHADOWSOCKS = true ]]; then
			info "Restart Shadowsocks_python..."
			/etc/init.d/shadowsocks_python restart
		fi
		if [[ \$SHADOWSOCKSR = true ]]; then
			info "Restart Shadowsocks_R..."
			/etc/init.d/shadowsocks_r restart
		fi
	}
	add_user() {
		# Add user to general list
		if [[ -n \$(grep -E "\$1 " \$GENERAL_USER_LIST) ]]; then
			sed -i "s_^\(\$1 \).*_\1\$2_" \$GENERAL_USER_LIST
		else
			echo "\$1 \$2" >> \$GENERAL_USER_LIST
		fi
		# Add to every VPN
		if [[ \$STRONGSWAN = true ]]; then
			if [[ -n \$(grep -E "\$1\ %any\ :\ EAP" \$STRONGSWAN_USER_LIST) ]]; then
				sed -i "s_^\(\$1 %any : EAP \).*_\1\"\$2\"_" \$STRONGSWAN_USER_LIST
				info "Updated StrongSwan User <\$1> password to <\$2>"
			else
				echo "\$1 %any : EAP \\"\$2\\"" >> \$STRONGSWAN_USER_LIST
				info "Added StrongSwan User <\$1> password <\$2>"
			fi
		fi
		if [[ \$OPENCONNECT = true ]]; then
			if [[ -n \$(grep -E "\$1:.*:.*" \$OPENCONNECT_USER_LIST) ]]; then
				echo "\$2 \$2"| tr " " "\n" | /usr/bin/ocpasswd -c \$OPENCONNECT_USER_LIST \$1
				info "Updated OpenConnect User <\$1> password to <\$2>"
			else
				echo "\$2 \$2"| tr " " "\n" | /usr/bin/ocpasswd -c \$OPENCONNECT_USER_LIST \$1
				info "Added OpenConnect User <\$1> password <\$2>"
			fi
		fi
		if [[ \$SHADOWSOCKS = true ]]; then
			python /usr/bin/ss_vpnuser -a \$1
			info "Added user \$1 to Shadowsocks_python..."
			# Update general list
			if [[ -n \$(grep -E "\$1 " \$GENERAL_USER_LIST) ]]; then
				if [[ ! -n \$(grep "\$1 .* SS_PORT=" \$GENERAL_USER_LIST) ]]; then
					user_port_number=\$(grep "\$1" $SS_PYTHON_CONFIGFILE | sed "s/.*\"\(.*\)\":.*/\1/")
					sed -e "/^\$1 .*/s/\$/ SS_PORT=\$user_port_number/" -i \$GENERAL_USER_LIST
				fi
			fi
		fi
		if [[ \$SHADOWSOCKSR = true ]]; then
			python /usr/bin/ssr_vpnuser -a \$1
			info "Added user \$1 to Shadowsocks_R..."
			# Update general list
			if [[ -n \$(grep -E "\$1 " \$GENERAL_USER_LIST) ]]; then
				if [[ ! -n \$(grep "\$1 .* SSR_PORT=" \$GENERAL_USER_LIST) ]]; then
					user_port_number=\$(grep "\$1" $SSR_CONFIGFILE | sed "s/.*\"\(.*\)\":.*/\1/")
					sed -e "/^\$1 .*/s/\$/ SSR_PORT=\$user_port_number/" -i \$GENERAL_USER_LIST
				fi
			fi
		fi
		restart_vpns
		grep "\$1" \$GENERAL_USER_LIST 
	}
	del_user() {
		# delete user from general list
		if [[ -n \$(grep -E "\$1 " \$GENERAL_USER_LIST) ]]; then
			sed -i "/^\$1.*/d" \$GENERAL_USER_LIST
			info "Delete user from general list"
		else
			info "User not in general list"
		fi
		# delete from every VPN
		if [[ \$STRONGSWAN = true ]]; then
			if [[ -n \$(grep -E "\$1\ %any\ :\ EAP" \$STRONGSWAN_USER_LIST) ]]; then
				sed -i "/^\$1.*/d" \$STRONGSWAN_USER_LIST
				sed -i "/^\$/d" \$STRONGSWAN_USER_LIST
				info "StrongSwan User <\$1> deleted"
			else
				info "StrongSwan User <\$1> don't exist, skip delete"
			fi
		fi
		if [[ \$OPENCONNECT = true ]]; then
			if [[ -n \$(grep -E "\$1:.*:.*" \$OPENCONNECT_USER_LIST) ]]; then
				ocpasswd -c \$OPENCONNECT_USER_LIST -d \$1
				info "OpenConnect User <\$1> deleted"
			else
				info "OpenConnect User <\$1> don't exist, skip delete"
			fi
		fi
		if [[ \$SHADOWSOCKS = true ]]; then
			python /usr/bin/ss_vpnuser -d \$1
			info "Deleted user <\$1> from Shadowsocks_python..."
		fi
		if [[ \$SHADOWSOCKSR = true ]]; then
			python /usr/bin/ssr_vpnuser -d \$1
			info "Deleted user <\$1> from Shadowsocks_R..."
		fi
		restart_vpns
	}

	# Parse command
	POSITIONAL=()
	[[ \$# -eq 0 ]] && show_help
	while [[ \$# -gt 0 ]]
	do 
	key="\$1"
	case \$key in
		help|-h|--help)
			show_help
			exit 0
		;;
		adduser|-a|--adduser)
			if ( [[ -n "\$2" && -n "\$3" ]] ); then
				add_user \$2 \$3
			else
				exception "Need username and password for adding user"
			fi
			shift
			shift
			shift
		;;
		deluser|-d|--deluser)
			if [[ -n "\$2" ]]; then
				del_user \$2
			else
				exception "Need username for deleting user"
			fi
			shift
			shift
		;;
		listuser|-l|--listuser)
			echo -e "\033[0;32mUserList: \033[0m"
			cat \$GENERAL_USER_LIST | awk '{print $1}'
			shift
		;;
		restart|-r|--restart)
			echo "Restart VPNs..."
			restart_vpns
		;;
		*)
			POSITIONAL+=("\$1")
			shift
		;;
	esac
	done
	set -- "\${POSITIONAL[@]}"
	if [[ -n \$1 ]]; then
		warning "Unknown arguments: \$1"
		show_help
	fi
	# End of Parse Command
EOF
	chmod 755 /usr/sbin/vpnuser
	# Create a  file to store general user info
	echo "${ADMIN_EMAIL} ${ADMIN_EMAIL} SS_PORT=${SS_PYTHON_PORT_START} SSR_PORT=${SSR_PORT_START}" > /etc/vpnuser
	chmod 700 /etc/vpnuser
	info "General user command: 'vpnuser' generated. "

	# Print out generate username-password information
	info ""
	info_highlight "Server Hostname: " "${VPN_HOSTNAME}"
	if [[ $STRONGSWAN = true ]]; then
		info "******************************** StrongSwan ********************************"
		info_highlight "StrongSwan default username: " "${ADMIN_EMAIL}"
		info_highlight "StrongSwan default password: " "${ADMIN_EMAIL}"
	fi
	if [[ $OPENCONNECT = true ]]; then
		info "******************************** OpenConnect ********************************"
		info_highlight "OpenConnect default username: " "${ADMIN_EMAIL}"
		info_highlight "OpenConnect default password: " "${ADMIN_EMAIL}"
	fi
	if [[ $SHADOWSOCKS = true ]]; then
		info "******************************** Shadowsocks ********************************"
		info_highlight "Shadowsocks default cipher: " "${SS_PYTHON_CIPHER}"
		info_highlight "Shadowsocks default port: " "${SS_PYTHON_PORT_START}"
		info_highlight "Shadowsocks default password: " "${ADMIN_EMAIL}"
	fi
	if [[ $SHADOWSOCKSR = true ]]; then
		info "******************************** ShadowsocksR ********************************"
		info_highlight "ShadowsocksR default cipher: " "${SSR_CIPHER}"
		info_highlight "ShadowsocksR default protocol: " "${SSR_PROTOCOL}"
		info_highlight "ShadowsocksR default OBFS: " "${SSR_OBFS}"
		info_highlight "ShadowsocksR default port: " "${SSR_PORT_START}"
		info_highlight "ShadowsocksR default password: " "${ADMIN_EMAIL}"
	fi
	info ""
	info "You can use 'sudo vpnuser -a <username> <password>' to add user or 'sudo vpnuser -d <username>' to delete user"

	# POST Processing
	service ssh restart
	service unattended-upgrades restart
fi # End of Installation Process



# Uninstall Process
if [[ $UNINSTALL_VPN = true ]]; then
	# Remove Everything in LIFO order

	# Remove user operation command and general user list
	rm -rf /usr/bin/ss_vpnuser
	rm -rf /usr/bin/ssr_vpnuser
	rm -rf /etc/vpnuser # This is general user list
	rm -rf /usr/sbin/vpnuser

	# Clear Client Script
	info "Clear Scripts for Client..."
	if [[ -d "${SCRIPT_DIR}/StrongSwan_Clients/" ]]; then
		[[ ! -f "${SCRIPT_DIR}/StrongSwan_Clients/StrongSwan_Client_iOS_macOS.mobileconfig" ]] || rm -f "${SCRIPT_DIR}/StrongSwan_Clients/StrongSwan_Client_iOS_macOS.mobileconfig"
		[[ ! -f "${SCRIPT_DIR}/StrongSwan_Clients/StrongSwan_Client_Ubuntu.sh" ]] || rm -f "${SCRIPT_DIR}/StrongSwan_Clients/StrongSwan_Client_Ubuntu.sh"
		[[ ! -f "${SCRIPT_DIR}/StrongSwan_Clients/StrongSwan_Client_Win10.ps1" ]] || rm -f "${SCRIPT_DIR}/StrongSwan_Clients/StrongSwan_Client_Win10.ps1"
		if [[ -n "$(find "${SCRIPT_DIR}/StrongSwan_Clients" -maxdepth 0 -type d -empty)" ]]; then
			rm -rf "${SCRIPT_DIR}/StrongSwan_Clients"
		fi
	fi
	info "Scripts Removed"
	
	# Remove StrongSwan
	info "Start to remove StrongSwan... "
	ipsec stop
	apt_remove "strongswan strongswan-starter libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins"
	apt_remove "strongswan strongswan-starter libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins"
	info "StrongSwan Removed"

	# Remove OpenConnect
	if [[ $OC_INSTALL_FROM_SOURCE = true ]]; then
		# Force stop if ocserv is still running
		Oc_pid=$(pidof ocserv)
		if [[ ! -z $Oc_pid ]]; then
			for Pid in $Oc_pid
			do
				kill -9 $Pid >> $LOG_DIR 2>&1
				if [[ $? -eq 0 ]]; then
					info "Killed running ocserv..."
				else
					warning "Cannot kill running ocserv..."
				fi
			done
		fi
		rm -rf /etc/ocserv
		rm -rf /usr/sbin/ocserv
		rm -rf /etc/init.d/ocserv
		rm -rf /usr/bin/occtl
		rm -rf /usr/bin/ocpasswd
		info "OpenConnect Removed"
	else
		# Uninstall OpenConnect through apt
		apt_remove "ocserv"
		info "OpenConnect Removed through apt"
		#exception "Please install OpenConnect through source...This part is not tested yet"
	fi
	apt_remove "libgmp3-dev libwrap0-dev libpam0g-dev libdbus-1-dev libnl-route-3-dev libopts25-dev libnl-nf-3-dev libreadline-dev libpcl1-dev libtalloc-dev libev-dev liboath-dev nettle-dev libseccomp-dev liblz4-dev libgeoip-dev libkrb5-dev libradcli-dev libgnutls28-dev gnutls-bin protobuf-c-compiler"

	# Remove Shadowsocks_python
	/etc/init.d/shadowsocks_python stop
	update-rc.d -f shadowsocks_python remove
	if [[ -f /etc/shadowsocks_python/shadowsocks_install.log ]]; then
		cat /etc/shadowsocks_python/shadowsocks_install.log | xargs rm -rf
	fi
	rm -rf /etc/shadowsocks_python
	rm -rf /etc/init.d/shadowsocks_python
	rm -rf /var/run/shadowsocks.pid
	rm -rf /var/log/shadowsocks.log
	info "Shadowsocks_python Removed"

	# Remove Shadowsocks_r
	/etc/init.d/shadowsocks_r stop
	update-rc.d -f shadowsocks_r remove
	rm -rf /etc/shadowsocks_r
	rm -rf /usr/bin/shadowsocks_r
	rm -rf /etc/init.d/shadowsocks_r
	info "Shadowsocks_R Removed"

	# Remove Let's Encrypt Certificate
	info "Remove Let's Encrypt Certificate. If you don't want to remove certificate left it blank. Be careful..."
	read -p "Enter you hostname: " VPN_HOSTNAME
	certbot revoke --cert-path /etc/letsencrypt/live/$VPN_HOSTNAME/cert.pem --delete-after-revoke >> $LOG_DIR 2>&1
	sed -e 's/* * * * 7 root certbot -q renew//' -i.original /etc/crontab
	info "Certificate Removed"

	# Clear Firewall Settings
	info "Start to Clear Firewall Settings..."
	iptables -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT >> $LOG_DIR 2>&1 # accept anything already accepted 
	iptables -D INPUT -i lo -j ACCEPT >> $LOG_DIR 2>&1 # accept anything on loopback interface
	iptables -D INPUT -m state --state INVALID -j DROP >> $LOG_DIR 2>&1 # Drop invalid packets
	iptables -D INPUT -i $INTERFACE -m state --state NEW -m recent --update --seconds 60 --hitcount 30 -j DROP >> $LOG_DIR 2>&1
	iptables -D INPUT -i $INTERFACE -m state --state NEW -m recent --set >> $LOG_DIR 2>&1 # Set limit for repeated request from same IP
		# StrongSwan Firewall Rules
		iptables -D INPUT -p udp -m udp --dport 500 -j ACCEPT >> $LOG_DIR 2>&1 # Accept IPSec/NAT-T for StrongSwan VPN
		iptables -D INPUT -p udp -m udp --dport 4500 -j ACCEPT >> $LOG_DIR 2>&1
		iptables -D FORWARD --match policy --pol ipsec --dir in --proto esp -s $STRONGSWAN_VPN_IPPOOL -j ACCEPT >> $LOG_DIR 2>&1  # Forward VPN traffic anywhere
		iptables -D FORWARD --match policy --pol ipsec --dir out --proto esp -d $STRONGSWAN_VPN_IPPOOL -j ACCEPT >> $LOG_DIR 2>&1 
		iptables -t mangle -D FORWARD --match policy --pol ipsec --dir in -s $STRONGSWAN_VPN_IPPOOL -o $INTERFACE -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360 >> $LOG_DIR 2>&1  # Reduce MTU/MSS values for dumb VPN clients
		iptables -t nat -D POSTROUTING -s $STRONGSWAN_VPN_IPPOOL -o $INTERFACE -m policy --pol ipsec --dir out -j ACCEPT >> $LOG_DIR 2>&1  # Exempt IPsec traffic from Masquerade
		iptables -t nat -D POSTROUTING -s $STRONGSWAN_VPN_IPPOOL -o $INTERFACE -j MASQUERADE >> $LOG_DIR 2>&1  # Masquerade VPN traffic over interface
		# OpenConnect Firewal Rules
		iptables -D INPUT -p udp -m udp --dport $OC_PORT -m comment --comment "ocserv-udp" -j ACCEPT >> $LOG_DIR 2>&1 
		iptables -D INPUT -p tcp -m tcp --dport $OC_PORT -m comment --comment "ocserv-tcp" -j ACCEPT >> $LOG_DIR 2>&1 
		iptables -D FORWARD -s $OC_VPN_IPPOOL -m comment --comment "ocserv-forward-in" -j ACCEPT
		iptables -D FORWARD -d $OC_VPN_IPPOOL -m comment --comment "ocesrv-forward-out" -j ACCEPT
		iptables -t mangle -D FORWARD -s $OC_VPN_IPPOOL -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "ocserv-mangle" -j TCPMSS --clamp-mss-to-pmtu # MSS fix
		iptables -t nat -D POSTROUTING -s $OC_VPN_IPPOOL ! -d $OC_VPN_IPPOOL -m comment --comment "ocserv-postrouting" -j MASQUERADE
		# Shadowsocks Firewall Rules
		iptables -A INPUT -p tcp -m multiport --dports $SS_PYTHON_PORT_START:$SS_PYTHON_PORT_END -j ACCEPT
		iptables -A INPUT -p udp -m multiport --dports $SS_PYTHON_PORT_START:$SS_PYTHON_PORT_END -j ACCEPT
		# Shadowoskcs-R firewall Rules
		iptables -A INPUT -p tcp -m multiport --dports $SSR_PORT_START:$SSR_PORT_END -j ACCEPT
		iptables -A INPUT -p udp -m multiport --dports $SSR_PORT_START:$SSR_PORT_END -j ACCEPT
	echo $SSH_ACCEPT_IP |tr ' ' '\n' | while read IP_RANGE ; do iptables -D INPUT -s $IP_RANGE -p tcp -m tcp --dport $SSH_PORT -j ACCEPT >> $LOG_DIR 2>&1 ; done   # Only accept ssh from certain IP rangse
	iptables -D INPUT -p tcp -m tcp --dport $SSH_PORT -j DROP  >> $LOG_DIR 2>&1 # Close SSH port to void ssh attack
	iptables -D INPUT -d $INTERFACE_IP/32 -p icmp -m icmp --icmp-type 8 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT  >> $LOG_DIR 2>&1 
	iptables -D OUTPUT -s $INTERFACE_IP/32 -p icmp -m icmp --icmp-type 8 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT >> $LOG_DIR 2>&1 
	iptables -D INPUT -j DROP  >> $LOG_DIR 2>&1  # Deny all other requests
	iptables -D FORWARD -j DROP  >> $LOG_DIR 2>&1 
	info "Firewall rules cleared"
	iptables-save > /etc/iptables/rules.v4
	iptables-save > /etc/iptables/rules.v6
	info "Firewall persistent updated"

	# Purge apt, will keep packages from official repository
	info "Removing certbot apt repository..."
	apt_install ppa-purge
	add-apt-repository -y ppa:certbot/certbot >> $LOG_DIR 2>&1
	ppa-purge -y ppa:certbot/certbot >> $LOG_DIR 2>&1
	add-apt-repository --remove ppa:certbot/certbot -y >> $LOG_DIR 2>&1
	apt_remove ppa-purge
fi

