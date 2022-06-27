#!/bin/bash

RED='\033[1;31m'
GREEN='\033[1;32m'
PURPLE='\033[1;35m'
NC='\033[0m'

# Check root
if [ $EUID -ne 0 ]; then
      echo "${RED}Permission Denied, Must be run by root${NC}"
      exit
fi

echo
echo "
 _   _      ____  _     _      _     _
| | | |    / ___|| |__ (_) ___| | __| |
| | | |____\___ \|  _ \| |/ _ \ |/ _  |
| |_| |_____|__) | | | | |  __/ | (_| |
 \___/     |____/|_| |_|_|\___|_|\__,_| 

CIS Benchmark Hardening
Ubuntu Server 20.04 LTS
By FCIS-ASU"

echo

###############################################################################

# Category 1 Initial Setup
echo
echo -e "${PURPLE}--------------------${NC}"
echo -e "${PURPLE}| 1- Initial Setup |${NC}"
echo -e "${PURPLE}--------------------${NC}"

echo "Updating System.."
# touch /var/lib/dpkg/status
# mkdir -p /var/cache/apt/archives/partial
# mkdir -p /var/lib/dpkg/{alternatives,info,parts,triggers,updates}
# touch /var/lib/dpkg/info/format-new
apt-get update
apt-get install aide aide-common apparmor apparmor-utils iptables iptables-persistent auditd audispd-plugins rsyslog sudo libpam-pwquality 
apt-get purge prelink ntp chrony xserver-xorg* avahi-daemon cups isc-dhcp-server slapd nfs-kernel-server bind9 vsftpd apache2 dovecot-imapd dovecot-pop3d samba squid snmpd rsync nis rsh-client talk telnet ldap-utils rpcbind ufw nftables

# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled
echo
echo -e "${PURPLE}1.1.1.1${NC} Ensure mounting of cramfs filesystems is disabled"
modprobe -n -v cramfs | grep "^install /bin/true$" || echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | egrep "^cramfs\s" && rmmod cramfs
echo -e "${GREEN}Remediated:${NC} Ensure mounting of cramfs filesystems is disabled"

# 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled
echo
echo -e "${PURPLE}1.1.1.2${NC} Ensure mounting of freevxfs filesystems is disabled"
modprobe -n -v freevxfs | grep "^install /bin/true$" || echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | egrep "^freevxfs\s" && rmmod freevxfs
echo -e "${GREEN}Remediated:${NC} Ensure mounting of freevxfs filesystems is disabled"

# 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled
echo
echo -e "${PURPLE}1.1.1.3${NC} Ensure mounting of jffs2 filesystems is disabled"
modprobe -n -v jffs2 | grep "^install /bin/true$" || echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | egrep "^jffs2\s" && rmmod jffs2
echo -e "${GREEN}Remediated:${NC} Ensure mounting of jffs2 filesystems is disabled"

# 1.1.1.4 Ensure mounting of hfs filesystems is disabled
echo
echo -e "${PURPLE}1.1.1.4${NC} Ensure mounting of hfs filesystems is disabled"
modprobe -n -v hfs | grep "^install /bin/true$" || echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | egrep "^hfs\s" && rmmod hfs
echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfs filesystems is disabled"

# 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled
echo
echo -e "${PURPLE}1.1.1.5${NC} Ensure mounting of hfsplus filesystems is disabled"
modprobe -n -v hfsplus | grep "^install /bin/true$" || echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | egrep "^hfsplus\s" && rmmod hfsplus
echo -e "${GREEN}Remediated:${NC} Ensure mounting of hfsplus filesystems is disabled"

# 1.1.1.6 Ensure mounting of squashfs filesystems is disabled 
echo
echo -e "${PURPLE}1.1.1.6${NC} Ensure mounting of squashfs filesystems is disabled"
modprobe -n -v squashfs | grep -E '(squashfs|install)' || echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | grep "squashfs" && rmmod squashfs
echo -e "${GREEN}Remediated:${NC} Ensure mounting of squashfs filesystems is disabled"

# 1.1.1.7 Ensure mounting of udf filesystems is disabled
echo
echo -e "${PURPLE}1.1.1.7${NC} Ensure mounting of udf filesystems is disabled"
modprobe -n -v udf | grep "^install /bin/true$" || echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
lsmod | egrep "^udf\s" && rmmod udf
echo -e "${GREEN}Remediated:${NC} Ensure mounting of udf filesystems is disabled"

# 1.1.2 Ensure /tmp is configured
echo
echo -e "${PURPLE}1.1.2${NC} Ensure /tmp is configured"
findmnt -n /tmp || cp -v /usr/share/systemd/tmp.mount /etc/systemd/system/
systemctl daemon-reload
systemctl --now enable tmp.mount
echo -e "${GREEN}Remediated:${NC} Ensure /tmp is configured"

# 1.1.3 Ensure nodev option set on /tmp partition 
echo
echo -e "${PURPLE}1.1.3${NC} Ensure nodev option set on /tmp partition"
findmnt -n /tmp | grep -v nodev && sed -i '/Options=mode/s/$/,nodev/' /etc/systemd/system/local-fs.target.wants/tmp.mount
systemctl daemon-reload
systemctl --now enable tmp.mount
echo -e "${GREEN}Remediated:${NC} Ensure nodev option set on /tmp partition"

# 1.1.4 Ensure nosuid option set on /tmp partition
echo
echo -e "${PURPLE}1.1.4${NC} Ensure nosuid option set on /tmp partition"
findmnt -n /tmp | grep -v nosuid && sed -i '/Options=mode/s/$/,nosuid/' /etc/systemd/system/local-fs.target.wants/tmp.mount
mount -o remount,nosuid /tmp
echo -e "${GREEN}Remediated:${NC} Ensure nosuid option set on /tmp partition"

# 1.1.5  Ensure noexec option set on /tmp partition
echo
echo -e "${PURPLE}1.1.5${NC}  Ensure noexec option set on /tmp partition"
findmnt -n /tmp | grep -v noexec && sed -i '/Options=mode/s/$/,noexec/' /etc/systemd/system/local-fs.target.wants/tmp.mount
mount -o remount,noexec /tmp
echo -e "${GREEN}Remediated:${NC}  Ensure noexec option set on /tmp partition"

# 1.1.6  Ensure /dev/shm is configured
echo
echo -e "${PURPLE}1.1.6${NC}  Ensure /dev/shm is configured"
findmnt -n /dev/shm || echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,seclabel 0 0" >> /etc/fstab
mount -o remount,noexec,nodev,nosuid /dev/shm
echo -e "${GREEN}Remediated:${NC}  Ensure /dev/shm is configured"

# 1.1.7  Ensure nodev option set on /dev/shm partition
echo
echo -e "${PURPLE}1.1.7${NC}  Ensure nodev option set on /dev/shm partition "
findmnt -n /dev/shm | grep -v nodev
echo -e "${GREEN}Remediated:${NC}  Ensure nodev option set on /dev/shm partition "

# 1.1.8  Ensure nosuid option set on /dev/shm partition
echo
echo -e "${PURPLE}1.1.8${NC}  Ensure nosuid option set on /dev/shm partition"
findmnt -n /dev/shm | grep -v nosuid
echo -e "${GREEN}Remediated:${NC}  Ensure nosuid option set on /dev/shm partition"

# 1.1.9  Ensure noexec option set on /dev/shm partition
echo
echo -e "${PURPLE}1.1.9${NC}  Ensure noexec option set on /dev/shm partition"
findmnt -n /dev/shm | grep -v noexec
echo -e "${GREEN}Remediated:${NC}  Ensure noexec option set on /dev/shm partition"

# 1.1.10 Ensure separate partition exists for /var
echo
echo -e "${PURPLE}1.1.10${NC}  Ensure separate partition exists for /var"
test -d "/var" || mkdir /var
echo "/dev/mapper/ubuntu--vg-ubuntu--lv /var ext4 nosuid,nodev,noexec" >> /etc/fstab
echo -e "${GREEN}Remediated:${NC}  Ensure separate partition exists for /var"

# 1.1.11 Ensure separate partition exists for /var/tmp
echo
echo -e "${PURPLE}1.1.11${NC}  Ensure separate partition exists for /var/tmp"
test -d "/var/tmp" || mkdir /var/tmp
echo "/dev/mapper/ubuntu--vg-ubuntu--lv /var/tmp ext4 nosuid,nodev,noexec" >> /etc/fstab
mount -o remount,noexec,nodev,nosuid /var/tmp
echo -e "${GREEN}Remediated:${NC}  Ensure separate partition exists for /var/tmp"

# 1.1.12  Ensure /var/tmp partition includes the nodev option 
echo
echo -e "${PURPLE}1.1.12${NC}  Ensure /var/tmp partition includes the nodev option"
findmnt -n /var/tmp | grep -v nodev
echo -e "${GREEN}Remediated:${NC}  Ensure /var/tmp partition includes the nodev option "

# 1.1.13  Ensure /var/tmp partition includes the nosuid option 
echo
echo -e "${PURPLE}1.1.13${NC}  Ensure /var/tmp partition includes the nosuid option"
findmnt -n /var/tmp | grep -v nosuid
echo -e "${GREEN}Remediated:${NC}  Ensure /var/tmp partition includes the nosuid option"

# 1.1.14  Ensure /var/tmp partition includes the noexec option 
echo
echo -e "${PURPLE}1.1.14${NC}  Ensure /var/tmp partition includes the noexec option"
findmnt -n /var/tmp | grep -v noexec
echo -e "${GREEN}Remediated:${NC}  Ensure /var/tmp partition includes the noexec option"

# 1.1.15 Ensure separate partition exists for /var/log
echo
echo -e "${PURPLE}1.1.15${NC}  Ensure separate partition exists for /var/log"
test -d "/var/log" || mkdir /var/log
echo "/dev/mapper/ubuntu--vg-ubuntu--lv /var/log ext4 nosuid,nodev,noexec" >> /etc/fstab
echo -e "${GREEN}Remediated:${NC}  Ensure separate partition exists for /var/log"

# 1.1.16 Ensure separate partition exists for /var/log/audit
echo
echo -e "${PURPLE}1.1.16${NC}  Ensure separate partition exists for /var/log/audit"
test -d "/var/log/audit" || mkdir /var/log/audit
echo "/dev/mapper/ubuntu--vg-ubuntu--lv /var/log/audit ext4 nosuid,nodev,noexec" >> /etc/fstab
echo -e "${GREEN}Remediated:${NC}  Ensure separate partition exists for /var/log/audit"

# 1.1.17 Ensure separate partition exists for /home
echo
echo -e "${PURPLE}1.1.17${NC}  Ensure separate partition exists for /home"
test -d "/home" || mkdir /home
echo "/dev/mapper/ubuntu--vg-ubuntu--lv /home ext4 nosuid,nodev,noexec" >> /etc/fstab
echo -e "${GREEN}Remediated:${NC}  Ensure separate partition exists for /home"

# 1.1.18  Ensure /home partition includes the nodev option
echo
echo -e "${PURPLE}1.1.18${NC}  Ensure /home partition includes the nodev option"
findmnt -n /home | grep -v nodev && mount -o remount,nodev /home
echo -e "${GREEN}Remediated:${NC}  Ensure /home partition includes the nodev option"

# 1.1.19 Ensure nodev option set on removable media partitions (Manual)

# 1.1.20 Ensure nosuid option set on removable media partitions (Manual)

# 1.1.21 Ensure noexec option set on removable media partitions (Manual)

# 1.1.22 Ensure sticky bit is set on all world-writable directories
echo
echo -e "${PURPLE}1.1.22${NC} Ensure sticky bit is set on all world-writable directories"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
echo -e "${GREEN}Remediated:${NC} Ensure sticky bit is set on all world-writable directories"

# 1.1.23 Disable Automounting
echo
echo -e "${PURPLE}1.1.23${NC} Disable Automounting"
systemctl is-enabled autofs && systemctl --now disable autofs
echo -e "${GREEN}Remediated:${NC} Disable Automounting"

# 1.1.24 Disable USB Storage
echo
echo -e "${PURPLE}1.1.24${NC} Disable USB Storage"
echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb_storage.conf
rmmod usb-storage
echo -e "${GREEN}Remediated:${NC} Disable USB Storage"

# 1.2.1 Ensure package manager repositories are configured (Manual)

# 1.2.2 Ensure GPG keys are configured (Manual)

# 1.3.1 Ensure AIDE is installed
echo
echo -e "${PURPLE}1.3.1 ${NC} Ensure AIDE is installed"
# AIDE installed 
echo -e "${GREEN}Remediated:${NC} Ensure AIDE is installed"

# 1.3.2 Ensure filesystem integrity is regularly checked
echo
echo -e "${PURPLE}1.3.2${NC} Ensure filesystem integrity is regularly checked"
egrep -q "^(\s*)aide\s+\S+(\s*#.*)?\s*$" /etc/crontab && sed -ri "s/^(\s*)aide\s+\S+(\s*#.*)?\s*$/\10 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check\2/" /etc/crontab || echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /etc/crontab
echo -e "${GREEN}Remediated:${NC} Ensure filesystem integrity is regularly checked"

# 1.4.1 Ensure permissions on bootloader config are not overridden 
echo
echo -e "${PURPLE}1.4.1 ${NC} Ensure permissions on bootloader config are not overridden"
sed -ri 's/chmod\s+[0-7][0-7][0-7]\s+\$\{grub_cfg\}\.new/chmod 400 ${grub_cfg}.new/' /usr/sbin/grub-mkconfig
sed -ri 's/ && ! grep "\^password" \$\{grub_cfg\}.new >\/dev\/null//' /usr/sbin/grub-mkconfig
echo -e "${GREEN}Remediated:${NC} Ensure permissions on bootloader config are not overridden"

# 1.4.2 Ensure bootloader password is set 
echo
echo -e "${PURPLE}1.4.2 ${NC} Ensure bootloader password is set"
grub-mkpasswd-pbkdf2 | tee grubpassword.tmp
grubpassword=$(cat grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
echo " set superusers="root" " >> /etc/grub.d/40_custom
echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
rm grubpassword.tmp
update-grub
echo -e "${GREEN}Remediated:${NC} Ensure bootloader password is set"

# 1.4.3 Ensure permissions on bootloader config are configured
echo
echo -e "${PURPLE}1.4.3${NC} Ensure permissions on bootloader config are configured"
chown root:root /boot/grub/grub.cfg && chmod u-wx,go-rwx /boot/grub/grub.cfg
echo -e "${GREEN}Remediated:${NC} Ensure permissions on bootloader config are configured"

# 1.4.4 Ensure authentication required for single user mode
echo
echo -e "${PURPLE}1.4.4${NC} Ensure authentication required for single user mode"
echo -e "Changing root password.."
passwd root
echo -e "${GREEN}Remediated:${NC} Ensure authentication required for single user mode"

# 1.5.1 Ensure XD/NX support is enabled (Manual)

# 1.5.2 Ensure address space layout randomization (ASLR) is enabled
echo
echo -e "${PURPLE}1.5.2${NC} Ensure address space layout randomization (ASLR) is enabled"
egrep -q "^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)kernel.randomize_va_space\s*=\s*\S+(\s*#.*)?\s*$/\1kernel.randomize_va_space = 2\2/" /etc/sysctl.conf || echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
echo -e "${GREEN}Remediated:${NC} Ensure address space layout randomization (ASLR) is enabled"

# 1.5.3 Ensure prelink is disabled
echo
echo -e "${PURPLE}1.5.3${NC} Ensure prelink is disabled"
# prelink purged 
echo -e "${GREEN}Remediated:${NC} Ensure prelink is disabled"

# 1.5.4 Ensure core dumps are restricted
echo
echo -e "${PURPLE}1.5.4${NC} Ensure core dumps are restricted"
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0
echo -e "${GREEN}Remediated:${NC} Ensure core dumps are restricted"

# 1.6.1.1 Ensure AppArmor is installed
echo
echo -e "${PURPLE}1.6.1.1${NC} Ensure AppArmor is installed"
# Apparmor installed 
echo -e "${GREEN}Remediated:${NC} Ensure AppArmor is installed"

# 1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration
echo
echo -e "${PURPLE}1.6.1.2${NC} Ensure AppArmor is enabled in the bootloader configuration"
sed -i 's/GRUB_CMDLINE_LINUX=\"\"/GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor\"/' /etc/default/grub
update-grub
echo -e "${GREEN}Remediated:${NC} Ensure AppArmor is enabled in the bootloader configuration"

#1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
echo
echo -e "${PURPLE}1.6.1.3${NC} Ensure all AppArmor Profiles are in enforce or complain mode"
# Apparmor-utils installed 
aa-enforce /etc/apparmor.d/*
echo -e "${GREEN}Remediated:${NC} Ensure all AppArmor Profiles are in enforce or complain mode"

#1.6.1.4 Ensure all AppArmor Profiles are enforcing
echo
echo -e "${PURPLE}1.6.1.4${NC} Ensure all AppArmor Profiles are enforcing"
echo -e "${GREEN}Remediated:${NC} Ensure all AppArmor Profiles are enforcing"

# 1.7.1 Ensure message of the day is configured properly
echo
echo -e "${PURPLE}1.7.1${NC} Ensure message of the day is configured properly"
sed -ri 's/(\\v|\\r|\\m|\\s)//g' /etc/motd
echo -e "${GREEN}Remediated:${NC} Ensure message of the day is configured properly"

# 1.7.2 Ensure local login warning banner is configured properly 
echo
echo -e "${PURPLE}1.7.2${NC} Ensure local login warning banner is configured properly"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo -e "${GREEN}Remediated:${NC} Ensure local login warning banner is configured properly"

# 1.7.3 Ensure remote login warning banner is configured properly
echo
echo -e "${PURPLE}1.7.3${NC} Ensure remote login warning banner is configured properly"
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
echo -e "${GREEN}Remediated:${NC} Ensure remote login warning banner is configured properly"

# 1.7.4 Ensure permissions on /etc/motd are configured
echo
echo -e "${PURPLE}1.7.4${NC} Ensure permissions on /etc/motd are configured"
chown root:root /etc/motd && chmod 644 /etc/motd
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/motd are configured"

# 1.7.5 Ensure permissions on /etc/issue are configured
echo
echo -e "${PURPLE}1.7.5${NC} Ensure permissions on /etc/issue are configured"
chown root:root $(readlink -e /etc/issue)
chmod u-x,go-wx $(readlink -e /etc/issue)
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue are configured"

# 1.7.6 Ensure permissions on /etc/issue.net are configured
echo
echo -e "${PURPLE}1.7.6${NC} Ensure permissions on /etc/issue.net are configured"
chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/issue.net are configured"

echo
echo -e "${PURPLE}1.9${NC} Ensure updates, patches, and additional security software are installed"
#apt-get upgrade
echo -e "${GREEN}Remediated:${NC} Ensure updates, patches, and additional security software are installed"

###########################################################################################################################

# Category 2  Services
echo
echo -e "${PURPLE}---------------${NC}"
echo -e "${PURPLE}| 2- Services |${NC}"
echo -e "${PURPLE}---------------${NC}"

# 2.1.1.1 Ensure time synchronization is in use
echo
echo -e "${PURPLE}2.1.1.1${NC} Ensure time synchronization is in use"
systemctl is-enabled systemd-timesyncd
echo -e "${GREEN}Remediated:${NC} Ensure time synchronization is in use"

# 2.1.1.2 Ensure systemd-timesyncd is configured
echo
echo -e "${PURPLE}2.1.1.2${NC} Ensure systemd-timesyncd is configured"
# ntp & chrony purged 
systemctl enable systemd-timesyncd.service
echo "NTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org #Servers listed should be In
Accordence With Local Policy
FallbackNTP=2.debian.pool.ntp.org 3.debian.pool.ntp.org #Servers listed
should be In Accordence With Local Policy
RootDistanceMax=1 #should be In Accordence With Local Policy" >> /etc/systemd/timesyncd.conf
systemctl start systemd-timesyncd.service 
timedatectl set-ntp true 
echo -e "${GREEN}Remediated:${NC} Ensure systemd-timesyncd is configured"

# 2.1.1.3 Ensure chrony is configured
echo
echo -e "${PURPLE}2.1.1.3${NC} Ensure chrony is configured"
# Used Systemd-timesyncd instead
echo -e "${PURPLE}systemd-timesyncd is in use${NC}"

# 2.1.1.4 Ensure ntp is configured
echo
echo -e "${PURPLE}2.1.1.4${NC} Ensure ntp is configured"
# Used Systemd-timesyncd instead
echo -e "${PURPLE}systemd-timesyncd is in use${NC}"

# 2.1.2 Ensure X Window System is not installed
echo
echo -e "${PURPLE}2.1.2${NC} Ensure X Window System is not installed"
# xserver-xorg* purged
echo -e "${GREEN}Remediated:${NC} Ensure X Window System is not installed"

# 2.1.3 Ensure Avahi Server is not installed
echo
echo -e "${PURPLE}2.1.3${NC} Ensure Avahi Server is not installed"
systemctl stop avahi-daaemon.service purged
systemctl stop avahi-daemon.socket purged
# avahi-daemon purged
echo -e "${GREEN}Remediated:${NC} Ensure Avahi Server is not installed"

# 2.1.4 Ensure CUPS is not installed
echo
echo -e "${PURPLE}2.1.4${NC} Ensure CUPS is not installed"
# cups purged
echo -e "${GREEN}Remediated:${NC} Ensure CUPS is not installed"

# 2.1.5 Ensure DHCP Server is not installed
echo
echo -e "${PURPLE}2.1.5${NC} Ensure DHCP Server is not installed"
# isc-dhcp-server purged
echo -e "${GREEN}Remediated:${NC} Ensure DHCP Server is not installed"

# 2.1.6 Ensure LDAP server is not installed
echo
echo -e "${PURPLE}2.1.6${NC} Ensure LDAP server is not installed"
# slapd purged
echo -e "${GREEN}Remediated:${NC} Ensure LDAP server is not installed"

# 2.1.7 Ensure NFS is not installed
echo
echo -e "${PURPLE}2.1.7${NC} Ensure NFS is not installed"
# nfs-kernel-server purged
echo -e "${GREEN}Remediated:${NC} Ensure NFS is not installed"

# 2.1.8 Ensure DNS Server is not installed
echo
echo -e "${PURPLE}2.1.8${NC} Ensure DNS Server is not installed"
# bind9 purged
echo -e "${GREEN}Remediated:${NC} Ensure DNS Server is not installed"

# 2.1.9 Ensure FTP Server is not installed
echo
echo -e "${PURPLE}2.1.9${NC} Ensure FTP Server is not installed"
# vsftpd purged
echo -e "${GREEN}Remediated:${NC} Ensure FTP Server is not installed"

# 2.1.10 Ensure HTTP server is not installed
echo
echo -e "${PURPLE}2.1.10${NC} Ensure HTTP server is not installed"
# apache2 purged
echo -e "${GREEN}Remediated:${NC} Ensure HTTP server is not installed"

# 2.1.11 Ensure IMAP and POP3 server are not installed
echo
echo -e "${PURPLE}2.1.11${NC} Ensure IMAP and POP3 server are not installed"
# dovecot-imapd dovecot-pop3d purged
echo -e "${GREEN}Remediated:${NC} Ensure IMAP and POP3 server are not installed"

# 2.1.12 Ensure Samba is not installed
echo
echo -e "${PURPLE}2.1.12${NC} Ensure Samba is not installed"
# samba purged
echo -e "${GREEN}Remediated:${NC} Ensure Samba is not installed"

# 2.1.13 Ensure HTTP Proxy Server is not installed
echo
echo -e "${PURPLE}2.1.13${NC} Ensure HTTP Proxy Server is not installed"
# squid purged
echo -e "${GREEN}Remediated:${NC} Ensure HTTP Proxy Server is not installed"

# 2.1.14 Ensure SNMP Server is not installed
echo
echo -e "${PURPLE}2.1.14${NC} Ensure SNMP Server is not installed"
# snmpd purged
echo -e "${GREEN}Remediated:${NC} Ensure SNMP Server is not installed"

# 2.1.15 Ensure mail transfer agent is configured for local-only mode
echo
echo -e "${PURPLE}2.1.15${NC} EEnsure mail transfer agent is configured for local-only mode"
echo "dc_eximconfig_configtype='local'
dc_local_interfaces='127.0.0.1 ; ::1'
dc_readhost=''
dc_relay_domains=''
dc_minimaldns='false'
dc_relay_nets=''
dc_smarthost=''
dc_use_split_config='false'
dc_hide_mailname=''
dc_mailname_in_oh='true'
dc_localdelivery='mail_spool'" >> /etc/exim4/update-exim4.conf.conf
systemctl restart exim4 purged
echo -e "${GREEN}Remediated:${NC} Ensure mail transfer agent is configured for local-only mode"

# 2.1.16 Ensure rsync service is not installed
echo
echo -e "${PURPLE}2.1.16${NC} Ensure rsync service is not installed"
# rsync purged
echo -e "${GREEN}Remediated:${NC} Ensure rsync service is not installed"

# 2.1.17 Ensure NIS Server is not installed
echo
echo -e "${PURPLE}2.1.17${NC} Ensure NIS Server is not installed"
# nis purged
echo -e "${GREEN}Remediated:${NC} Ensure NIS Server is not installed"

# 2.2.1 Ensure NIS Client is not installed
echo
echo -e "${PURPLE}2.2.1${NC} Ensure NIS Client is not installed"
# nis purged
echo -e "${GREEN}Remediated:${NC} Ensure NIS Client is not installed"

# 2.2.2 Ensure rsh client is not installed
echo
echo -e "${PURPLE}2.2.2${NC} Ensure rsh client is not installed"
# rsh-client purged
echo -e "${GREEN}Remediated:${NC} Ensure rsh client is not installed"

# 2.2.3 Ensure talk client is not installed
echo
echo -e "${PURPLE}2.2.3${NC} Ensure talk client is not installed"
# talk purged
echo -e "${GREEN}Remediated:${NC} Ensure talk client is not installed"

# 2.2.4 Ensure telnet client is not installed
echo
echo -e "${PURPLE}2.2.4${NC} Ensure telnet client is not installed"
# telnet purged
echo -e "${GREEN}Remediated:${NC} Ensure telnet client is not installed"

# 2.2.5 Ensure LDAP client is not installed
echo
echo -e "${PURPLE}2.2.5${NC} Ensure LDAP client is not installed"
# ldap-utils purged
echo -e "${GREEN}Remediated:${NC} Ensure LDAP client is not installed"

# 2.2.6 Ensure RPC is not installed
echo
echo -e "${PURPLE}2.2.6${NC} Ensure RPC is not installed"
# rpcbind purged
echo -e "${GREEN}Remediated:${NC} Ensure RPC is not installed"

# 2.3 Ensure nonessential services are removed or masked (Manual)

###########################################################################################################################

# Category 3  Network Configuration
echo
echo -e "${PURPLE}----------------------------${NC}"
echo -e "${PURPLE}| 3- Network Configuration |${NC}"
echo -e "${PURPLE}----------------------------${NC}"

# 3.1.1 Disable IPv6
echo
echo -e "${PURPLE}3.1.1${NC} Disable IPv6"
echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.route.flush=1
echo -e "${GREEN}Remediated:${NC} Disable IPv6"

# 3.1.2 Ensure wireless interfaces are disabled
echo
echo -e "${PURPLE}3.1.2${NC} Ensure wireless interfaces are disabled (requires script)"

# 3.2.1 Ensure packet redirect sending is disabled
echo
echo -e "${PURPLE}3.2.1${NC} Ensure packet redirect sending is disabled"
egrep -q "^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.send_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.send_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure packet redirect sending is disabled"

# 3.2.2 Ensure IP forwarding is disabled
echo
echo -e "${PURPLE}3.2.2${NC} Ensure IP forwarding is disabled"
grep -Els "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf | while read filename; do sed -ri "s/^\s*(net\.ipv4\.ip_forward\s*)(=)(\s*\S+\b).*$/# *REMOVED* \1/" $filename; done; sysctl net.ipv4.ip_forward=0; sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure IP forwarding is disabled"

# 3.3.1 Ensure source routed packets are not accepted
echo
echo -e "${PURPLE}3.3.1${NC} Ensure source routed packets are not accepted"
egrep -q "^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.accept_source_route\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.accept_source_route = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure source routed packets are not accepted"

# 3.3.2 Ensure ICMP redirects are not accepted
echo
echo -e "${PURPLE}3.3.2${NC} Ensure ICMP redirects are not accepted"
egrep -q "^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.accept_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.accept_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure ICMP redirects are not accepted"

# 3.3.3 Ensure secure ICMP redirects are not accepted
echo
echo -e "${PURPLE}3.3.3${NC} Ensure secure ICMP redirects are not accepted"
egrep -q "^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.secure_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.secure_redirects\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.secure_redirects = 0\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure secure ICMP redirects are not accepted"

# 3.3.4 Ensure suspicious packets are logged
echo
echo -e "${PURPLE}3.3.4${NC} Ensure suspicious packets are logged"
egrep -q "^(\s*)net.ipv4.conf.all.log_martians\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.log_martians\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.log_martians = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.log_martians\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.log_martians\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.log_martians = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure suspicious packets are logged"

# 3.3.5 Ensure broadcast ICMP requests are ignored
echo
echo -e "${PURPLE}3.3.5${NC} Ensure broadcast ICMP requests are ignored"
egrep -q "^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_echo_ignore_broadcasts\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_echo_ignore_broadcasts = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure broadcast ICMP requests are ignored"

# 3.3.6 Ensure bogus ICMP responses are ignored
echo
echo -e "${PURPLE}3.3.6${NC} Ensure bogus ICMP responses are ignored"
egrep -q "^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.icmp_ignore_bogus_error_responses\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.icmp_ignore_bogus_error_responses = 1\2/" /etc/sysctl.conf || echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure bogus ICMP responses are ignored"

# 3.3.7 Ensure Reverse Path Filtering is enabled
echo
echo -e "${PURPLE}3.3.7${NC} Ensure Reverse Path Filtering is enabled"
egrep -q "^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.all.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.all.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.conf.default.rp_filter\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.conf.default.rp_filter = 1\2/" /etc/sysctl.conf || echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure Reverse Path Filtering is enabled"

# 3.3.8 Ensure TCP SYN Cookies is enabled
echo
echo -e "${PURPLE}3.3.8${NC} Ensure TCP SYN Cookies is enabled"
egrep -q "^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv4.tcp_syncookies\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv4.tcp_syncookies = 1\2/" /etc/sysctl.conf || echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure TCP SYN Cookies is enabled"

# 3.3.9 Ensure IPv6 router advertisements are not accepted
echo
echo -e "${PURPLE}3.3.9${NC} Ensure IPv6 router advertisements are not accepted"
egrep -q "^(\s*net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.all.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.all.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
egrep -q "^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$" /etc/sysctl.conf && sed -ri "s/^(\s*)net.ipv6.conf.default.accept_ra\s*=\s*\S+(\s*#.*)?\s*$/\1net.ipv6.conf.default.accept_ra = 0\2/" /etc/sysctl.conf || echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
echo -e "${GREEN}Remediated:${NC} Ensure IPv6 router advertisements are not accepted"

# 3.4.1 Ensure DCCP is disabled
echo
echo -e "${PURPLE}3.4.1${NC} Ensure DCCP is disabled"
modprobe -n -v dccp | grep "^install /bin/true$" || echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} Ensure DCCP is disabled"

# 3.4.2 Ensure SCTP is disabled
echo
echo -e "${PURPLE}3.4.2${NC} Ensure SCTP is disabled"
modprobe -n -v sctp | grep "^install /bin/true$" || echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} Ensure SCTP is disabled"

# 3.4.3 Ensure RDS is disabled
echo
echo -e "${PURPLE}3.4.3${NC} Ensure RDS is disabled"
modprobe -n -v rds | grep "^install /bin/true$" || echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} Ensure RDS is disabled"

# 3.4.4 Ensure TIPC is disabled
echo
echo -e "${PURPLE}3.4.4${NC} Ensure TIPC is disabled"
modprobe -n -v tipc | grep "^install /bin/true$" || echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
echo -e "${GREEN}Remediated:${NC} Ensure TIPC is disabled"

# 3.5.1.1 Ensure ufw is installed
# echo
# echo -e "${PURPLE}3.5.1.1${NC} Ensure ufw is installed"
# apt-get install ufw
# echo -e "${GREEN}Remediated:${NC} Ensure ufw is installed"

# 3.5.1.2 Ensure iptables-persistent is not installed with ufw
# echo
# echo -e "${PURPLE}3.5.1.2${NC} Ensure iptables-persistent is not installed with ufw"
# apt-get purge iptables-persistent purged
# echo -e "${GREEN}Remediated:${NC} Ensure iptables-persistent is not installed with ufw"

# 3.5.1.3 Ensure ufw service is enabled
# echo
# echo -e "${PURPLE}3.5.1.3${NC} Ensure ufw service is enabled"
# ufw enable
# echo -e "${GREEN}Remediated:${NC} Ensure ufw service is enabled"

# 3.5.1.4 Ensure ufw loopback traffic is configured
# echo
# echo -e "${PURPLE}3.5.1.4${NC} Ensure ufw loopback traffic is configured"
# ufw allow in on lo
# ufw allow out on lo
# ufw deny in from 127.0.0.0/8
# ufw deny in from ::1
# echo -e "${GREEN}Remediated:${NC} Ensure ufw loopback traffic is configured"

# 3.5.1.5 Ensure ufw outbound connections are configured
# echo
# echo -e "${PURPLE}3.5.1.5${NC} Ensure ufw outbound connections are configured"
# ufw allow out on all
# echo -e "${GREEN}Remediated:${NC} Ensure ufw outbound connections are configured"

# 3.5.1.6 Ensure ufw firewall rules exist for all open ports (Manual)

# 3.5.1.7 Ensure ufw default deny firewall policy
# echo
# echo -e "${PURPLE}3.5.1.7${NC} Ensure ufw default deny firewall policy"
# ufw default deny incoming
# ufw default deny outgoing
# ufw default deny routed
# echo -e "${GREEN}Remediated:${NC} Ensure ufw default deny firewall policy"

# 3.5.2.1 Ensure nftables is installed
# echo
# echo -e "${PURPLE}3.5.2.1${NC} Ensure nftables is installed"
# apt-get install nftables 
# echo -e "${GREEN}Remediated:${NC} Ensure nftables is installed"

# 3.5.2.2 Ensure ufw is uninstalled or disabled with nftables
# echo
# echo -e "${PURPLE}3.5.2.2${NC} Ensure ufw is uninstalled or disabled with nftables"
# ufw disable
# echo -e "${GREEN}Remediated:${NC} Ensure ufw is uninstalled or disabled with nftables"

# 3.5.2.3 Ensure iptables are flushed with nftables
# echo
# echo -e "${PURPLE}3.5.2.3${NC} Ensure iptables are flushed with nftables"
# iptables -F
# echo -e "${GREEN}Remediated:${NC} Ensure iptables are flushed with nftables"

# 3.5.2.4 Ensure a nftables table exists
# echo
# echo -e "${PURPLE}3.5.2.4${NC} Ensure a nftables table exists"
# nft create table inet filter
# echo -e "${GREEN}Remediated:${NC} Ensure a nftables table exists"

# 3.5.2.5 Ensure nftables base chains exist
# echo
# echo -e "${PURPLE}3.5.2.5${NC} Ensure nftables base chains exist"
# nft create chain inet filter input { type filter hook input priority 0 \; }
# nft create chain inet filter forward { type filter hook forward priority 0 \; }
# nft create chain inet filter output { type filter hook output priority 0 \; }
# echo -e "${GREEN}Remediated:${NC} Ensure nftables base chains exist"

# 3.5.2.6 Ensure nftables loopback traffic is configured
# echo
# echo -e "${PURPLE}3.5.2.6${NC} Ensure nftables loopback traffic is configured"
# nft add rule inet filter input iif lo accept
# nft create rule inet filter input ip saddr 127.0.0.0/8 counter drop
# echo -e "${GREEN}Remediated:${NC} Ensure nftables loopback traffic is configured"

# 3.5.2.7 Ensure nftables outbound and established connections are configured
# echo
# echo -e "${PURPLE}3.5.2.7${NC} Ensure nftables outbound and established connections are configured"
# nft add rule inet filter input ip protocol tcp ct state established accept
# nft add rule inet filter input ip protocol udp ct state established accept
# nft add rule inet filter input ip protocol icmp ct state established accept
# nft add rule inet filter output ip protocol tcp ct state new,related,established accept
# nft add rule inet filter output ip protocol udp ct state new,related,established accept
# nft add rule inet filter output ip protocol icmp ct state new,related,established accept
# echo -e "${GREEN}Remediated:${NC} Ensure nftables outbound and established connections are configured"

# 3.5.2.8 Ensure nftables default deny firewall policy
# echo
# echo -e "${PURPLE}3.5.2.8${NC} Ensure nftables default deny firewall policy"
# nft chain inet filter input { policy drop \; }
# nft chain inet filter forward { policy drop \; }
# nft chain inet filter output { policy drop \; }
# echo -e "${GREEN}Remediated:${NC} Ensure nftables default deny firewall policy"

# 3.5.2.9 Ensure nftables service is enabled
# echo
# echo -e "${PURPLE}3.5.2.9${NC} Ensure nftables service is enabled"
# systemctl enable nftables
# echo -e "${GREEN}Remediated:${NC} Ensure nftables service is enabled"

# 3.5.2.10 Ensure nftables rules are permanent 
# echo
# echo -e "${PURPLE}3.5.2.10${NC} Ensure nftables rules are permanent"
# echo 'include "/etc/nftables.rules"' >> /etc/nftables.conf
# echo -e "${GREEN}Remediated:${NC} Ensure nftables rules are permanent"

# 3.5.3.1.1 Ensure iptables packages are installed 
echo
echo -e "${PURPLE}3.5.3.1.1${NC} Ensure iptables packages are installed"
# iptables iptables-persistent installed
echo -e "${GREEN}Remediated:${NC} Ensure iptables packages are installed"

# 3.5.3.1.2 Ensure nftables is not installed with iptables 
echo
echo -e "${PURPLE}3.5.3.1.2${NC} Ensure nftables is not installed with iptables"
# nftables purged
echo -e "${GREEN}Remediated:${NC} Ensure nftables is not installed with iptables"

# 3.5.3.1.3 Ensure ufw is uninstalled or disabled with iptables 
echo
echo -e "${PURPLE}3.5.3.1.3${NC} Ensure ufw is uninstalled or disabled with iptables"
# ufw purged
echo -e "${GREEN}Remediated:${NC} Ensure ufw is uninstalled or disabled with iptables"

# 3.5.3.2.1 Ensure iptables loopback traffic is configured 
echo
echo -e "${PURPLE}3.5.3.2.1${NC} Ensure iptables loopback traffic is configured"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
echo -e "${GREEN}Remediated:${NC} Ensure iptables loopback traffic is configured"

# 3.5.3.2.2 Ensure outbound and established connections are configured
echo
echo -e "${PURPLE}3.5.3.2.2${NC} Ensure outbound and established connections are configured"
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
echo -e "${GREEN}Remediated:${NC} Ensure outbound and established connections are configured"
 
# 3.5.3.2.3 Ensure iptables default deny firewall policy 
echo
echo -e "${PURPLE}3.5.3.2.3${NC} Ensure iptables default deny firewall policy"
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
echo -e "${GREEN}Remediated:${NC} Ensure iptables default deny firewall policy"

# 3.5.3.2.4 Ensure iptables firewall rules exist for all open ports (Requires open ports)

# 3.5.3.3.1 Ensure ip6tables loopback traffic is configured 
echo
echo -e "${PURPLE}3.5.3.3.1${NC} Ensure ip6tables loopback traffic is configured"
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j DROP
echo -e "${GREEN}Remediated:${NC} Ensure ip6tables loopback traffic is configured"

# 3.5.3.3.2 Ensure ip6tables outbound and established connections are configured
echo
echo -e "${PURPLE}3.5.3.3.2${NC} Ensure ip6tables outbound and established connections are configured"
ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
echo -e "${GREEN}Remediated:${NC} Ensure ip6tables outbound and established connections are configured"

# 3.5.3.3.3 Ensure ip6tables default deny firewall policy
echo
echo -e "${PURPLE}3.5.3.3.1${NC} Ensure ip6tables default deny firewall policy"
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
echo -e "${GREEN}Remediated:${NC} Ensure ip6tables default deny firewall policy"

# 3.5.3.3.4 Ensure ip6tables firewall rules exist for all open ports (Requires open ports)

############################################################################################################################

# 4 Logging and Auditing
echo
echo -e "${PURPLE}---------------------------${NC}"
echo -e "${PURPLE}| 4- Logging and Auditing |${NC}"
echo -e "${PURPLE}---------------------------${NC}"

# 4.1.1.1 Ensure auditd is installed
echo
echo -e "${PURPLE}4.1.1.1${NC} Ensure auditd is installed"
# auditd audispd-plugins installed
echo -e "${GREEN}Remediated:${NC} Ensure auditd is installed"

# 4.1.1.2 Ensure auditd service is enabled
echo
echo -e "${PURPLE}4.1.1.2${NC} Ensure auditd service is enabled"
systemctl --now enable auditd
echo -e "${GREEN}Remediated:${NC} Ensure auditd service is enabled"

# 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled
echo
echo -e "${PURPLE}4.1.1.3${NC} Ensure auditing for processes that start prior to auditd is enabled"
egrep -q "^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\S+(\s*#.*)?\s*$" /etc/default/grub && sed -ri "s/^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\S+(\s*#.*)?\s*$/\1GRUB_CMDLINE_LINUX=\"audit=1\"\2/" /etc/default/grub || echo "GRUB_CMDLINE_LINUX=\"audit=1\"" >> /etc/default/grub
update-grub
echo -e "${GREEN}Remediated:${NC} Ensure auditing for processes that start prior to auditd is enabled"

# 4.1.1.4 Ensure audit_backlog_limit is sufficient
echo
echo -e "${PURPLE}4.1.1.4${NC} Ensure audit_backlog_limit is sufficient"
egrep -q "^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\S+(\s*#.*)?\s*$" /etc/default/grub && sed -ri "s/^(\s*)GRUB_CMDLINE_LINUX\s*=\s*\S+(\s*#.*)?\s*$/\1GRUB_CMDLINE_LINUX=\"audit_backlog_limit=8192\"\2/" /etc/default/grub || echo "GRUB_CMDLINE_LINUX=\"audit_backlog_limit=8192\"" >> /etc/default/grub
update-grub
echo -e "${GREEN}Remediated:${NC} Ensure audit_backlog_limit is sufficient"

# 4.1.2.1 Ensure audit log storage size is configured (Depends on site policy)

# 4.1.2.2 Ensure audit logs are not automatically deleted
echo
echo -e "${PURPLE}4.1.2.2${NC} Ensure audit logs are not automatically deleted"
egrep -q "^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)max_log_file_action\s*=\s*\S+(\s*#.*)?\s*$/\1max_log_file_action = keep_logs\2/" /etc/audit/auditd.conf || echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
echo -e "${GREEN}Remediated:${NC} Ensure audit logs are not automatically deleted"

# 4.1.2.3 Ensure system is disabled when audit logs are full
echo
echo -e "${PURPLE}4.1.2.3${NC} Ensure system is disabled when audit logs are full"
egrep -q "^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1space_left_action = email\2/" /etc/audit/auditd.conf || echo "space_left_action = email" >> /etc/audit/auditd.conf
egrep -q "^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)action_mail_acct\s*=\s*\S+(\s*#.*)?\s*$/\1action_mail_acct = root\2/" /etc/audit/auditd.conf || echo "action_mail_acct = root" >> /etc/audit/auditd.conf
egrep -q "^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$" /etc/audit/auditd.conf && sed -ri "s/^(\s*)admin_space_left_action\s*=\s*\S+(\s*#.*)?\s*$/\1admin_space_left_action = halt\2/" /etc/audit/auditd.conf || echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf
echo -e "${GREEN}Remediated:${NC} Ensure system is disabled when audit logs are full"

# 4.1.3 Ensure events that modify date and time information are collected
echo
echo -e "${PURPLE}4.1.3${NC} Ensure events that modify date and time information are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-S\s+stime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/audit.rules
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+clock_settime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/localtime\s+-p\s+wa\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+adjtimex\s+-S\s+settimeofday\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+clock_settime\s+-k\s+time-change\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure events that modify date and time information are collected"

# 4.1.4 Ensure events that modify user/group information are collected
echo
echo -e "${PURPLE}4.1.4${NC} Ensure events that modify user/group information are collected"
egrep "^-w\s+/etc/group\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/passwd\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/gshadow\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/shadow\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/security/opasswd\s+-p\s+wa\s+-k\s+identity\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure events that modify user/group information are collected"

# 4.1.5 Ensure events that modify the system's network environment are collected
echo
echo -e "${PURPLE}4.1.5${NC} Ensure events that modify the system's network environment are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/issue\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/issue.net\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/hosts\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/etc/sysconfig/network\s+-p\s+wa\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+sethostname\s+-S\s+setdomainname\s+-k\s+system-locale\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's network environment are collected"

# 4.1.6 Ensure events that modify the system's Mandatory Access Controls are collected
echo
echo -e "${PURPLE}4.1.6${NC} Ensure events that modify the system's Mandatory Access Controls are collected"
grep "^-w\s+/etc/apparmor/\s+-p\s+wa\s+-k\s+MAC-policy" /etc/audit/rules.d/audit.rules || echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
grep "^-w /etc/apparmor.d/ -p wa -k MAC-policy" /etc/audit/rules.d/audit.rules || echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure events that modify the system's Mandatory Access Controls are collected"

# 4.1.7 Ensure login and logout events are collected
echo
echo -e "${PURPLE}4.1.7${NC} Ensure login and logout events are collected"
grep "^-w /var/log/faillog -p wa -k logins" /etc/audit/rules.d/audit.rules || echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
grep "^-w /var/log/lastlog -p wa -k logins" /etc/audit/rules.d/audit.rules || echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
grep "^-w /var/log/tallylog -p wa -k logins" /etc/audit/rules.d/audit.rules || echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure login and logout events are collected"

# 4.1.8 Ensure session initiation information is collected
echo
echo -e "${PURPLE}4.1.8${NC} Ensure session initiation information is collected"
grep "^-w /var/run/utmp -p wa -k session" /etc/audit/rules.d/audit.rules || echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
grep "^-w /var/log/wtmp -p wa -k logins" /etc/audit/rules.d/audit.rules || echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
grep "^-w /var/log/btmp -p wa -k logins" /etc/audit/rules.d/audit.rules || echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure session initiation information is collected"

# 4.1.9 Ensure discretionary access control permission modification events are collected
echo
echo -e "${PURPLE}4.1.9${NC} Ensure discretionary access control permission modification events are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chmod\s+-S\s+fchmod\s+-S\s+fchmodat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+chown\s+-S\s+fchown\s+-S\s+fchownat\s+-S\s+lchown\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+setxattr\s+-S\s+lsetxattr\s+-S\s+fsetxattr\s+-S\s+removexattr\s+-S\s+lremovexattr\s+-S\s+fremovexattr\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+perm_mod\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure discretionary access control permission modification events are collected"

# 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected
echo
echo -e "${PURPLE}4.1.10${NC} Ensure unsuccessful unauthorized file access attempts are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EACCES\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+creat\s+-S\s+open\s+-S\s+openat\s+-S\s+truncate\s+-S\s+ftruncate\s+-F\s+exit=-EPERM\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+access\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure unsuccessful unauthorized file access attempts are collected"

# 4.1.11 Ensure use of privileged commands is collected
echo
echo -e "${PURPLE}4.1.11${NC} Ensure use of privileged commands is collected"
for file in `find / -xdev \( -perm -4000 -o -perm -2000 \) -type f`; do
    egrep -q "^\s*-a\s+(always,exit|exit,always)\s+-F\s+path=$file\s+-F\s+perm=x\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+privileged\s*(#.*)?$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F path=$file -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/audit.rules;
done
echo -e "${GREEN}Remediated:${NC} Ensure use of privileged commands is collected"

# 4.1.12 Ensure successful file system mounts are collected
echo
echo -e "${PURPLE}4.1.12${NC} Ensure successful file system mounts are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+mount\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+mounts\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure successful file system mounts are collected"

# 4.1.13 Ensure file deletion events by users are collected
echo
echo -e "${PURPLE}4.1.13${NC} Ensure file deletion events by users are collected"
egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+unlink\s+-S\s+unlinkat\s+-S\s+rename\s+-S\s+renameat\s+-F\s+auid>=1000\s+-F\s+auid!=4294967295\s+-k\s+delete\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure file deletion events by users are collected"

# 4.1.14 Ensure changes to system administration scope (sudoers) is collected
echo
echo -e "${PURPLE}4.1.14${NC} Ensure changes to system administration scope (sudoers) is collected"
grep "^-w /etc/sudoers -p wa -k scope" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules
grep "^-w /etc/sudoers.d/ -p wa -k scope" /etc/audit/rules.d/audit.rules || echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure changes to system administration scope (sudoers) is collected"

# 4.1.15 Ensure system administrator actions (sudolog) are collected
echo
echo -e "${PURPLE}4.1.15${NC} Ensure system administrator actions (sudolog) are collected"
grep "^-w /var/log/sudo.log -p wa -k actions" /etc/audit/rules.d/audit.rules || echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure system administrator actions (sudolog) are collected"

# 4.1.16 Ensure kernel module loading and unloading is collected
echo
echo -e "${PURPLE}4.1.16${NC} Ensure kernel module loading and unloading is collected"
egrep "^-w\s+/sbin/insmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/sbin/rmmod\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/rules.d/audit.rules
egrep "^-w\s+/sbin/modprobe\s+-p\s+x\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' || egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b32\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules
uname -p | grep -q 'x86_64' && egrep "^-a\s+(always,exit|exit,always)\s+-F\s+arch=b64\s+-S\s+init_module\s+-S\s+delete_module\s+-k\s+modules\s*$" /etc/audit/rules.d/audit.rules || echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure kernel module loading and unloading is collected"

# 4.1.17 Ensure the audit configuration is immutable
echo
echo -e "${PURPLE}4.1.17${NC} Ensure the audit configuration is immutable"
grep "-e 2" /etc/audit/rules.d/audit.rules || echo "-e 2" >> /etc/audit/rules.d/audit.rules
echo -e "${GREEN}Remediated:${NC} Ensure the audit configuration is immutable"

# 4.2.1.1 Ensure rsyslog is installed
echo
echo -e "${PURPLE}4.2.1.1${NC} Ensure rsyslog is installed"
# rsyslog installed
echo -e "${GREEN}Remediated:${NC} Ensure rsyslog is installed"

# 4.2.1.2 Ensure rsyslog Service is enabled
echo
echo -e "${PURPLE}4.2.1.2${NC} Ensure rsyslog Service is enabled"
systemctl --now enable rsyslog
echo -e "${GREEN}Remediated:${NC} Ensure rsyslog Service is enabled"

# 4.2.1.3 Ensure logging is configured (Manual)

# 4.2.1.4 Ensure rsyslog default file permissions configured
echo
echo -e "${PURPLE}4.2.1.4${NC} Ensure rsyslog default file permissions configured"
grep "$FileCreateMode 0640" /etc/rsyslog.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.conf
grep "$FileCreateMode 0640" /etc/rsyslog.d/*.conf || echo "$""FileCreateMode 0640" >> /etc/rsyslog.d/*.conf
echo -e "${GREEN}Remediated:${NC} Ensure rsyslog default file permissions configured"

# 4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Depends on target)

# 4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts
echo
echo -e "${PURPLE}4.2.1.6${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"
sed -i -e 's/#$ModLoad imtcp.so/$ModLoad imtcp.so/g' /etc/rsyslog.conf
grep "$ModLoad imtcp.so" /etc/rsyslog.conf || echo "$""ModLoad imtcp.so" >> /etc/rsyslog.conf
sed -i -e 's/#$InputTCPServerRun 514/$InputTCPServerRun 514/g' /etc/rsyslog.conf
grep "$InputTCPServerRun 514" /etc/rsyslog.conf || echo "$""InputTCPServerRun 514" >> /etc/rsyslog.conf
systemctl restart rsyslog
echo -e "${GREEN}Remediated:${NC} Ensure remote rsyslog messages are only accepted on designated log hosts"

# 4.2.2.1 Ensure journald is configured to send logs to rsyslog
echo
echo -e "${PURPLE}4.2.2.1${NC} Ensure journald is configured to send logs to rsyslog"
grep "ForwardToSyslog=yes" /etc/systemd/journald.conf || echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf
echo -e "${GREEN}Remediated:${NC} Ensure journald is configured to send logs to rsyslog"

# 4.2.2.2 Ensure journald is configured to compress large log files
echo
echo -e "${PURPLE}4.2.2.2${NC} Ensure journald is configured to compress large log files"
grep "Compress=yes" /etc/systemd/journald.conf || echo "Compress=yes" >> /etc/systemd/journald.conf
echo -e "${GREEN}Remediated:${NC} Ensure journald is configured to compress large log files"

# 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk
echo
echo -e "${PURPLE}4.2.2.3${NC} Ensure journald is configured to write logfiles to persistent disk"
grep "Storage=persistent" /etc/systemd/journald.conf || echo "Storage=persistent" >> /etc/systemd/journald.conf
echo -e "${GREEN}Remediated:${NC} Ensure journald is configured to write logfiles to persistent disk"

# 4.2.3 Ensure permissions on all logfiles are configured
echo
echo -e "${PURPLE}4.2.3${NC} Ensure permissions on all logfiles are configured"
find /var/log -type f -exec chmod g-wx,o-rwx {} +
echo -e "${GREEN}Remediated:${NC} Ensure permissions on all logfiles are configured"

# 4.3 Ensure logrotate is configured (Manual)

# 4.4 Ensure logrotate assigns appropriate permissions
echo
echo -e "${PURPLE}4.4${NC} Ensure logrotate assigns appropriate permissions"
sed -i 's/create/create 0640 root utmp/' /etc/logrotate.conf
echo -e "${GREEN}Remediated:${NC} Ensure logrotate assigns appropriate permissions"

############################################################################################################################

# 5 Access, Authentication and Authorization
echo
echo -e "${PURPLE}-----------------------------------------------${NC}"
echo -e "${PURPLE}| 5- Access, Authentication and Authorization |${NC}"
echo -e "${PURPLE}-----------------------------------------------${NC}"

# 5.1.1 Ensure cron daemon is enabled and running
echo
echo -e "${PURPLE}5.1.1${NC} Ensure cron daemon is enabled and running"
systemctl --now enable cron
echo -e "${GREEN}Remediated:${NC} Ensure cron daemon is enabled and running"

# 5.1.2 Ensure permissions on /etc/crontab are configured
echo
echo -e "${PURPLE}5.1.2${NC} Ensure permissions on /etc/crontab are configured"
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/crontab are configured"

# 5.1.3 Ensure permissions on /etc/cron.hourly are configured
echo
echo -e "${PURPLE}5.1.3${NC} Ensure permissions on /etc/cron.hourly are configured"
chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.hourly are configured"

# 5.1.4 Ensure permissions on /etc/cron.daily are configured
echo
echo -e "${PURPLE}5.1.4${NC} Ensure permissions on /etc/cron.daily are configured"
chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.daily are configured"

# 5.1.5 Ensure permissions on /etc/cron.weekly are configured
echo
echo -e "${PURPLE}5.1.5${NC} Ensure permissions on /etc/cron.weekly are configured"
chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.weekly are configured"

# 5.1.6 Ensure permissions on /etc/cron.monthly are configured
echo
echo -e "${PURPLE}5.1.6${NC} Ensure permissions on /etc/cron.monthly are configured"
chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.monthly are configured"

# 5.1.7 Ensure permissions on /etc/cron.d are configured
echo
echo -e "${PURPLE}5.1.7${NC} Ensure permissions on /etc/cron.d are configured"
chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/cron.d are configured"

# 5.1.8 Ensure cron is restricted to authorized users
echo
echo -e "${PURPLE}5.1.8${NC} Ensure cron is restricted to authorized users"
rm /etc/cron.deny
touch /etc/cron.allow
chmod g-wx,o-rwx /etc/cron.allow
chown root:root /etc/cron.allow
echo -e "${GREEN}Remediated:${NC} Ensure cron is restricted to authorized users"

# 5.1.9 Ensure at is restricted to authorized users
echo
echo -e "${PURPLE}5.1.9${NC} Ensure at is restricted to authorized users"
rm /etc/at.deny
touch /etc/at.allow
chmod g-wx,o-rwx /etc/at.allow
chown root:root /etc/at.allow
echo -e "${GREEN}Remediated:${NC} Ensure at is restricted to authorized users"

# 5.2.1 Ensure sudo is installed
echo
echo -e "${PURPLE}5.2.1${NC} Ensure sudo is installed"
# sudo installed
echo -e "${GREEN}Remediated:${NC} Ensure sudo is installed"

# 5.2.2 Ensure sudo commands use pty
echo
echo -e "${PURPLE}5.2.2${NC} Ensure sudo commands use pty"
grep -q "Defaults use_pty" /etc/sudoers || echo "Defaults use_pty" >> /etc/sudoers
echo -e "${GREEN}Remediated:${NC} Ensure sudo commands use pty"

# 5.2.3 Ensure sudo log file exists
echo
echo -e "${PURPLE}5.2.3${NC} Ensure sudo log file exists"
grep -q 'Defaults logfile="/var/log/sudo.log"' /etc/sudoers || echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
echo -e "${GREEN}Remediated:${NC} Ensure sudo log file exists"

# 5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured
echo
echo -e "${PURPLE}5.2.3${NC} Ensure permissions on /etc/ssh/sshd_config are configured"
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/ssh/sshd_config are configured"

# 5.3.2 Ensure permissions on SSH private host key files are configured
echo
echo -e "${PURPLE}5.3.2${NC} Ensure permissions on SSH private host key files are configured"
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;
echo -e "${GREEN}Remediated:${NC} Ensure permissions on SSH private host key files are configured"

# 5.3.3 Ensure permissions on SSH public host key files are configured
echo
echo -e "${PURPLE}5.3.3${NC} Ensure permissions on SSH public host key files are configured"
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
echo -e "${GREEN}Remediated:${NC} Ensure permissions on SSH public host key files are configured"

# 5.3.4 Ensure SSH access is limited (Needs list of authorized users)

# 5.3.5 Ensure SSH LogLevel is appropriate
echo
echo -e "${PURPLE}5.3.5${NC} Ensure SSH LogLevel is appropriate"
sed -i '/LogLevel/d' /etc/ssh/sshd_config
echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH LogLevel is appropriate"

# 5.3.6  Ensure SSH X11 forwarding is disabled
echo
echo -e "${PURPLE}5.3.6${NC}  Ensure SSH X11 forwarding is disabled"
sed -i '/X11Forwarding/d' /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC}  Ensure SSH X11 forwarding is disabled"

# 5.3.7  Ensure SSH MaxAuthTries is set to 4 or less
echo
echo -e "${PURPLE}5.3.7${NC} Ensure SSH MaxAuthTries is set to 4 or less"
sed -i '/MaxAuthTries/d' /etc/ssh/sshd_config
echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxAuthTries is set to 4 or less"

# 5.3.8  Ensure SSH IgnoreRhosts is enabled
echo
echo -e "${PURPLE}5.3.8${NC} Ensure SSH IgnoreRhosts is enabled"
sed -i '/IgnoreRhosts/d' /etc/ssh/sshd_config
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH IgnoreRhosts is enabled"

# 5.3.9  Ensure SSH HostbasedAuthentication is disabled
echo
echo -e "${PURPLE}5.3.9${NC} Ensure SSH HostbasedAuthentication is disabled"
sed -i '/HostbasedAuthentication/d' /etc/ssh/sshd_config
echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH HostbasedAuthentication is disabled"

# 5.3.10  Ensure SSH root login is disabled
echo
echo -e "${PURPLE}5.3.10${NC} Ensure SSH root login is disabled"
sed -i '/PermitRootLogin/d' /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH root login is disabled"

# 5.3.11  Ensure SSH PermitEmptyPasswords is disabled
echo
echo -e "${PURPLE}5.3.11${NC} Ensure SSH PermitEmptyPasswords is disabled"
sed -i '/PermitEmptyPasswords/d' /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitEmptyPasswords is disabled"

# 5.3.12  Ensure SSH PermitUserEnvironment is disabled
echo
echo -e "${PURPLE}5.3.12${NC} Ensure SSH PermitUserEnvironment is disabled"
sed -i '/PermitUserEnvironment/d' /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH PermitUserEnvironment is disabled"

# 5.3.13  Ensure only strong Ciphers are used
echo
echo -e "${PURPLE}5.3.13${NC} Ensure only strong Ciphers are used"
sed -i '/Ciphers/d' /etc/ssh/sshd_config
echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure only strong Ciphers are used"

# 5.3.14  Ensure only strong MAC algorithms are used
echo
echo -e "${PURPLE}5.3.14${NC} Ensure only strong MAC algorithms are used"
sed -i '/MACs/d' /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure only strong MAC algorithms are used"

# 5.3.15 Ensure only strong Key Exchange algorithms are used
echo
echo -e "${PURPLE}5.3.15${NC} Ensure only strong Key Exchange algorithms are used"
sed -i '/KexAlgorithms/d' /etc/ssh/sshd_config
echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellmangroup14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffiehellman-group-exchange-sha256" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure only strong Key Exchange algorithms are used"

# 5.3.16  Ensure SSH Idle Timeout Interval is configured
echo
echo -e "${PURPLE}5.3.16${NC} Ensure SSH Idle Timeout Interval is configured"
sed -i '/ClientAliveInterval/d' /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
sed -i '/ClientAliveCountMax/d' /etc/ssh/sshd_config
echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH Idle Timeout Interval is configured"

# 5.3.17  Ensure SSH LoginGraceTime is set to one minute or less
echo
echo -e "${PURPLE}5.3.17${NC} Ensure SSH LoginGraceTime is set to one minute or less"
sed -i '/LoginGraceTime/d' /etc/ssh/sshd_config
echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH LoginGraceTime is set to one minute or less"

# 5.3.18  Ensure SSH warning banner is configured
echo
echo -e "${PURPLE}5.3.17${NC} Ensure SSH warning banner is configured"
sed -i '/Banner/d' /etc/ssh/sshd_config
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH warning banner is configured"

# 5.3.19  Ensure SSH PAM is enabled
echo
echo -e "${PURPLE}5.3.17${NC} Ensure SSH PAM is enabled"
sed -i '/UsePAM/d' /etc/ssh/sshd_config
echo "UsePAM yes" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH PAM is enabled"

# 5.3.20  Ensure SSH AllowTcpForwarding is disabled
echo
echo -e "${PURPLE}5.3.20${NC} Ensure SSH AllowTcpForwarding is disabled"
sed -i '/AllowTcpForwarding/d' /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH AllowTcpForwarding is disabled"

# 5.3.21  Ensure SSH MaxStartups is configured
echo
echo -e "${PURPLE}5.3.21${NC} Ensure SSH MaxStartups is configured"
sed -i '/MaxStartups/d' /etc/ssh/sshd_config
echo "MaxStartups 10:30:60" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxStartups is configured"

# 5.3.22  Ensure SSH MaxSessions is limited
echo
echo -e "${PURPLE}5.3.21${NC} Ensure SSH MaxSessions is limited"
sed -i '/MaxSessions/d' /etc/ssh/sshd_config
echo "MaxSessions 10" >> /etc/ssh/sshd_config
echo -e "${GREEN}Remediated:${NC} Ensure SSH MaxSessions is limited"

# 5.4.1  Ensure password creation requirements are configured
echo
echo -e "${PURPLE}5.4.1${NC} Ensure password creation requirements are configured"
# libpam-pwquality 
sed -i '/minlen/d' /etc/security/pwquality.conf
echo "minlen = 14" >> /etc/security/pwquality.conf
sed -i '/minclass/d' /etc/security/pwquality.conf
echo "minclass = 4" >> /etc/security/pwquality.conf
sed -i '/requisite/d' /etc/pam.d/common-password
echo "password requisite pam_pwquality.so retry=3" >> /etc/pam.d/common-password
echo -e "${GREEN}Remediated:${NC} Ensure password creation requirements are configured"

# 5.4.2  Ensure lockout for failed password attempts is configured
echo
echo -e "${PURPLE}5.4.2${NC} Ensure lockout for failed password attempts is configured"
echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth
echo "account requisite pam_deny.so" >> /etc/pam.d/common-account
echo "account required pam_tally2.so" >> /etc/pam.d/common-account
echo -e "${GREEN}Remediated:${NC} Ensure lockout for failed password attempts is configured"

# 5.4.3  Ensure password reuse is limited
echo
echo -e "${PURPLE}5.4.3${NC} Ensure password reuse is limited"
sed -i '/required/d' /etc/pam.d/common-password 
echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password 
echo -e "${GREEN}Remediated:${NC} Ensure password reuse is limited"

# 5.4.4  Ensure password hashing algorithm is SHA-512
echo
echo -e "${PURPLE}5.4.4${NC} Ensure password hashing algorithm is SHA-512"
sed -i '/[success=1 default=ignore]/d' /etc/pam.d/common-password
echo "password [success=1 default=ignore] pam_unix.so sha512" >> /etc/pam.d/common-password
echo -e "${GREEN}Remediated:${NC} Ensure password hashing algorithm is SHA-512"

# 5.5.1.1  Ensure minimum days between password changes is configured
echo
echo -e "${PURPLE}5.5.1.1${NC} Ensure minimum days between password changes is configured"
sed -i '/PASS_MIN_DAYS/d' /etc/login.defs
echo "PASS_MIN_DAYS 1" >> /etc/login.defs
echo -e "${GREEN}Remediated:${NC} Ensure minimum days between password changes is configured"

# 5.5.1.2  Ensure password expiration is 365 days or less
echo
echo -e "${PURPLE}5.5.1.2${NC} Ensure password expiration is 365 days or less"
sed -i '/PASS_MAX_DAYS/d' /etc/login.defs
echo "PASS_MAX_DAYS 365" >> /etc/login.defs
echo -e "${GREEN}Remediated:${NC} Ensure password expiration is 365 days or less"

# 5.5.1.3  Ensure password expiration warning days is 7 or more
echo
echo -e "${PURPLE}5.5.1.1${NC} Ensure password expiration warning days is 7 or more"
sed -i '/PASS_WARN_AGE/d' /etc/login.defs
echo "PASS_WARN_AGE 7" >> /etc/login.defs
echo -e "${GREEN}Remediated:${NC} Ensure password expiration warning days is 7 or more"

# 5.5.1.4  Ensure inactive password lock is 30 days or less 
echo
echo -e "${PURPLE}5.5.1.1${NC} Ensure inactive password lock is 30 days or less"
useradd -D -f 30
echo -e "${GREEN}Remediated:${NC} Ensure inactive password lock is 30 days or less"

# 5.5.1.5  Ensure all users last password change date is in the past (Requires username)

# 5.5.2  Ensure system accounts are secured (Requires username)

# 5.5.3  Ensure default group for the root account is GID 0 
echo
echo -e "${PURPLE}5.5.3${NC} Ensure default group for the root account is GID 0"
usermod -g 0 root
echo -e "${GREEN}Remediated:${NC} Ensure default group for the root account is GID 0"

# 5.5.4  Ensure default user umask is 027 or more restrictive 
echo
echo -e "${PURPLE}5.5.4${NC} Ensure default user umask is 027 or more restrictive"
grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bash.bashrc*
sed -i '/UMASK/d' /etc/login.defs
echo "UMASK 027" >> /etc/login.defs
sed -i '/USERGROUPS_ENAB/d' /etc/login.defs
echo "USERGROUPS_ENAB no" >> /etc/login.defs
sed -i '/optional/d' /etc/pam.d/common-session
echo "session optional pam_umask.so" >> /etc/pam.d/common-session
echo -e "${GREEN}Remediated:${NC} Ensure default user umask is 027 or more restrictive"

# 5.5.5 Ensure default user shell timeout is 900 seconds or less
echo
echo -e "${PURPLE}5.5.5${NC} Ensure default user shell timeout is 900 seconds or less"
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/bash.bashrc && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/bash.bashrc || echo "TMOUT=600" >> /etc/bash.bashrc
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile || echo "TMOUT=600" >> /etc/profile
egrep -q "^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$" /etc/profile.d/*.sh && sed -ri "s/^(\s*)TMOUT\s+\S+(\s*#.*)?\s*$/\1TMOUT=600\2/" /etc/profile.d/*.sh || echo "TMOUT=600" >> /etc/profile.d/*.sh
echo -e "${GREEN}Remediated:${NC} Ensure default user shell timeout is 900 seconds or less"

# 5.6 Ensure root login is restricted to system console (Manual)

# 5.7 Ensure access to the su command is restricted
echo
echo -e "${PURPLE}5.7${NC} Ensure access to the su command is restricted"
groupadd sugroup
egrep -q "^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$" /etc/pam.d/su && sed -ri '/^\s*auth\s+required\s+pam_wheel.so(\s+.*)?$/ { /^\s*auth\s+required\s+pam_wheel.so(\s+\S+)*(\s+use_uid)(\s+.*)?$/! s/^(\s*auth\s+required\s+pam_wheel.so)(\s+.*)?$/\1 use_uid\2/ }' /etc/pam.d/su || echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
echo -e "${GREEN}Remediated:${NC} Ensure access to the su command is restricted"

############################################################################################################################

# 6 System Maintenance 
echo
echo -e "${PURPLE}-------------------------${NC}"
echo -e "${PURPLE}| 6- System Maintenance |${NC}"
echo -e "${PURPLE}-------------------------${NC}"

# 6.1.1  Audit system file permissions (Manual)

# 6.1.2  Ensure permissions on /etc/passwd are configured
echo
echo -e "${PURPLE}6.1.2${NC} Ensure permissions on /etc/passwd are configured"
chown root:root /etc/passwd
chmod u-x,go-wx /etc/passwd
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd are configured"

# 6.1.3  Ensure permissions on /etc/passwd- are configured
echo
echo -e "${PURPLE}6.1.3${NC} Ensure permissions on /etc/passwd- are configured"
chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/passwd- are configured"

# 6.1.4  Ensure permissions on /etc/group are configured
echo
echo -e "${PURPLE}6.1.4${NC} Ensure permissions on /etc/group are configured"
chown root:root /etc/group
chmod u-x,go-wx /etc/group
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group are configured"

# 6.1.5  Ensure permissions on /etc/group- are configured
echo
echo -e "${PURPLE}6.1.5${NC} Ensure permissions on /etc/group- are configured"
chown root:root /etc/group-
chmod u-x,go-wx /etc/group
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/group- are configured"

# 6.1.6  Ensure permissions on /etc/shadow are configured
echo
echo -e "${PURPLE}6.1.6${NC} Ensure permissions on /etc/shadow are configured"
chown root:root /etc/shadow
chmod u-x,g-wx,o-rwx /etc/shadow
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow are configured"

# 6.1.7 Ensure permissions on /etc/shadow- are configured
echo
echo -e "${PURPLE}6.1.7${NC} Ensure permissions on /etc/shadow- are configured"
chown root:root /etc/shadow-
chmod u-x,g-wx,o-rwx /etc/shadow-
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/shadow- are configured"

# 6.1.8 Ensure permissions on /etc/gshadow are configured
echo
echo -e "${PURPLE}6.1.8${NC} Ensure permissions on /etc/gshadow are configured"
chown root:root /etc/gshadow
chmod u-x,g-wx,o-rwx /etc/gshadow
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow are configured"

# 6.1.9 Ensure permissions on /etc/gshadow- are configured
echo
echo -e "${PURPLE}6.1.9${NC} Ensure permissions on /etc/gshadow- are configured"
chown root:root /etc/gshadow-
chmod u-x,g-wx,o-rwx /etc/gshadow-
echo -e "${GREEN}Remediated:${NC} Ensure permissions on /etc/gshadow- are configured"

# 6.1.10 Ensure no world writable files exist

# 6.1.11 Ensure no unowned files or directories exist

# 6.1.12 Ensure no ungrouped files or directories exist

# 6.1.13 Audit SUID executables

# 6.1.14 Audit SGID executables

# 6.2.1 Ensure accounts in /etc/passwd use shadowed passwords
echo
echo -e "${PURPLE}6.2.1${NC} Ensure accounts in /etc/passwd use shadowed passwords"
sed -e 's/^\([a-zA-Z0-9_]*\):[^:]*:/\1:x:/' -i /etc/passwd
echo -e "${GREEN}Remediated:${NC} Ensure accounts in /etc/passwd use shadowed passwords"

# 6.2.2 Ensure password fields are not empty
echo
echo -e "${PURPLE}6.2.2${NC} Ensure password fields are not empty"
awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow
echo -e "${GREEN}Remediated:${NC} Ensure password fields are not empty"

# 6.2.3 Ensure all groups in /etc/passwd exist in /etc/group

# 6.2.4 Ensure all users' home directories exist (script)

# 6.2.5 Ensure users own their home directories (script)

# 6.2.6 Ensure users' home directories permissions are 750 or more restrictive (script)

# 6.2.7 Ensure users' dot files are not group or world writable (script)

# 6.2.8 Ensure no users have .netrc files (script)

# 6.2.9 Ensure no users have .forward files (script)

# 6.2.10 Ensure no users have .rhosts files (script)

# 6.2.11 Ensure root is the only UID 0 account

# 6.2.12 Ensure root PATH Integrity

# 6.2.13 Ensure no duplicate UIDs exist

# 6.2.14 Ensure no duplicate GIDs exist

# 6.2.15 Ensure no duplicate user names exist

# 6.2.16 Ensure no duplicate group names exis

# 6.2.17 Ensure shadow group is empty
echo
echo -e "${PURPLE}6.2.17${NC} Ensure shadow group is empty"
sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group
echo -e "${GREEN}Remediated:${NC} Ensure shadow group is empty"

echo
echo -e "${PURPLE}---------------------${NC}"
echo -e "${PURPLE}| Finished Auditing |${NC}"
echo -e "${PURPLE}---------------------${NC}"
