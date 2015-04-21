#!/bin/bash

# CIS benchmark RHEL 7 audit
# Jan-Karel Visser 2015
#
# 20-04-2015 - Frank Spierings - Several bug fixes; grub2, grep mount, failing if-fi parts.
# 20-04-2015 - Frank Spierings - GPG Check alternative
# 20-04-2015 - Frank Spierings - SELinux; grep the output for the specific values.

echo '1.1.1 Create Separate Partition for /tmp (Scored)'
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab

echo '1.1.2 Set nodev option for /tmp Partition (Scored)'
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nodev 
mount | grep "[[:space:]]/tmp[[:space:]]" | grep nodev

echo '1.1.3 Set nosuid option for /tmp Partition (Scored)'
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nosuid
mount | grep "[[:space:]]/tmp[[:space:]]" | grep nosuid

echo '1.1.4 Set noexec option for /tmp Partition (Scored)'
grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep noexec 
mount | grep "[[:space:]]/tmp[[:space:]]" | grep noexec

echo '1.1.5 Create Separate Partition for /var (Scored)'
grep "[[:space:]]/var[[:space:]]" /etc/fstab

echo '1.1.6 Bind Mount the /var/tmp directory to /tmp (Scored)'
grep -e "^/tmp[[:space:]]" /etc/fstab | grep /var/tmp 
mount | grep -e "^/tmp[[:space:]]" | grep /var/tmp

echo '1.1.7 Create Separate Partition for /var/log (Scored)'
grep "[[:space:]]/var/log[[:space:]]" /etc/fstab

echo '1.1.8 Create Separate Partition for /var/log/audit (Scored)'
grep "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab

echo '1.1.9 Create Separate Partition for /home (Scored)'
grep "[[:space:]]/home[[:space:]]" /etc/fstab

echo '1.1.10 Add nodev Option to /home (Scored)'
grep "[[:space:]]/home[[:space:]]" /etc/fstab
mount | grep /home

echo '1.1.14 Add nodev Option to /dev/shm Partition (Scored)'
grep /dev/shm /etc/fstab | grep nodev
mount | grep /dev/shm | grep nodev

echo '1.1.15 Add nosuid Option to /dev/shm Partition (Scored)'
grep /dev/shm /etc/fstab | grep nosuid
mount | grep /dev/shm | grep nosuid

echo '1.1.16 Add noexec Option to /dev/shm Partition (Scored)'
grep /dev/shm /etc/fstab | grep noexec 
mount | grep /dev/shm | grep noexec

echo '1.1.17 Set Sticky Bit on All World-Writable Directories (Scored)'
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null

echo '1.2.2 Verify Red Hat GPG Key is Installed (Scored)'
rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey
echo '1.2.2 Verify Red Hat GPG Key is Installed (Scored) (ALTERNATIVE)'
rpm -qa gpg-pubkey* | xargs rpm -qi

echo '1.2.3 Verify that gpgcheck is Globally Activated (Scored)'
grep gpgcheck /etc/yum.conf

echo '1.3.1 Install AIDE (Scored)'
rpm -q aide

echo '1.3.2 Implement Periodic Execution of File Integrity (Scored)'
crontab -u root -l | grep aide

echo '1.4.1 Enable SELinux in /etc/grub.conf (Scored)'
grep selinux=0   /etc/grub.conf  2>/dev/null
grep enforcing=0 /etc/grub.conf  2>/dev/null
grep selinux=0   /etc/grub2.conf 2>/dev/null
grep enforcing=0 /etc/grub2.conf 2>/dev/null

echo '1.4.2 Set the SELinux State (Scored)'
grep SELINUX=enforcing /etc/selinux/config
/usr/sbin/sestatus | grep --color=never -i mode

echo '1.4.3 Set the SELinux Policy (Scored)'
grep SELINUXTYPE=targeted /etc/selinux/config
/usr/sbin/sestatus | grep --color=never -i 'policy name'

echo '1.4.4 Remove SETroubleshoot (Scored)'
rpm -q setroubleshoot

echo '1.4.5 Remove MCS Translation Service (mcstrans) (Scored)'
rpm -q mcstrans

echo '1.4.6 Check for Unconfined Daemons (Scored)'
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{print $NF}'
echo '1.4.6 Check for Unconfined Daemons (Scored) (ALTERNATIVE)'
ps -eo label,cmd | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" 

echo '1.5.1 Set User/Group Owner on /boot/grub2/grub.cfg (Scored)'
stat -L -c "%u %g" /boot/grub2/grub.cfg | egrep "0 0"

echo '1.5.2 Set Permissions on /etc/grub.conf (Scored)'
stat -L -c "%a" /boot/grub2/grub.cfg | egrep ".00"

echo '1.5.3 Set Boot Loader Password (Scored)'
grep "^set superusers" /boot/grub2/grub.cfg
grep "^password" /boot/grub2/grub.cfg

echo '1.6.1 Restrict Core Dumps (Scored)'
grep "hard core" /etc/security/limits.conf
sysctl fs.suid_dumpable

echo '1.6.1 Enable Randomized Virtual Memory Region Placement (Scored)'
sysctl kernel.randomize_va_space

echo '2.1.1 Remove telnet-server (Scored)'
rpm -q telnet-server

echo '2.1.2 Remove telnet Clients (Scored)'
rpm -q telnet

echo '2.1.3 Remove rsh-server (Scored)'
rpm -q rsh-server

echo '2.1.4 Remove rsh (Scored)'
rpm -q rsh

echo '2.1.5 Remove NIS Client (Scored)'
rpm -q ypbind

echo '2.1.6 Remove NIS Server (Scored)'
rpm -q ypserv

echo '2.1.7 Remove tftp (Scored)'
rpm -q tftp

echo '2.1.8 Remove tftp-server (Scored)'
rpm -q tftp-server

echo '2.1.9 Remove talk (Scored)'
rpm -q talk

echo '2.1.10 Remove talk-server (Scored)'
rpm -q talk-server

echo '2.1.11 Remove xinetd (Scored)'
rpm -q xinetd

echo '2.1.1* List all services (ALTERNATIVE)'
chkconfig --list
systemctl list-unit-files | grep '.service' 

echo '2.1.12 Disable chargen-dgram (Scored)'
chkconfig --list chargen-dgram

echo '2.1.13 Disable chargen-stream (Scored)'
chkconfig --list chargen-stream

echo '2.1.14 Disable daytime-dgram (Scored)'
chkconfig --list daytime-dgram

echo '2.1.15 Disable daytime-stream (Scored)'
chkconfig --list daytime-stream

echo '2.1.16 Disable echo-dgram (Scored)'
chkconfig --list echo-dgram

echo '2.1.17 Disable echo-stream (Scored)'
chkconfig --list echo-stream

echo '2.1.18 Disable tcpmux-server (Scored)'
chkconfig --list tcpmux-server

echo '3.1 Set Daemon umask (Scored)'
grep umask /etc/sysconfig/init

echo '3.2 Remove the X Window System (Scored)'
ls -l /usr/lib/systemd/system/default.target | grep graphical.target
rpm -q xorg-x11-server-common

echo '3.3 Disable Avahi Server (Scored)'
systemctl is-enabled avahi-daemon

echo '3.5 Remove DHCP Server (Scored)'
rpm -q dhcp

echo '3.6 Configure Network Time Protocol (NTP) (Scored)'
grep "restrict default" /etc/ntp.conf
grep "restrict -6 default" /etc/ntp.conf
grep "^server" /etc/ntp.conf
grep "ntp:ntp" /etc/sysconfig/ntpd

echo '3.16 Configure Mail Transfer Agent for Local-Only Mode (Scored)'
netstat -an | grep LIST | grep ":25[[:space:]]"

echo '4.1.1 Disable IP Forwarding (Scored)'
/sbin/sysctl net.ipv4.ip_forward

echo '4.1.2 Disable Send Packet Redirects (Scored)'
/sbin/sysctl net.ipv4.conf.all.send_redirects
/sbin/sysctl net.ipv4.conf.default.send_redirects

echo '4.2.1 Disable Source Routed Packet Acceptance (Scored)'
/sbin/sysctl net.ipv4.conf.all.accept_source_route
/sbin/sysctl net.ipv4.conf.default.accept_source_route

echo '4.2.2 Disable ICMP Redirect Acceptance (Scored)'
/sbin/sysctl net.ipv4.conf.all.accept_redirects
/sbin/sysctl net.ipv4.conf.default.accept_redirects

echo '4.2.3 Disable Secure ICMP Redirect Acceptance (Scored)'
/sbin/sysctl net.ipv4.conf.all.secure_redirects
/sbin/sysctl net.ipv4.conf.default.secure_redirects

echo '4.2.4 Log Suspicious Packets (Scored)'
/sbin/sysctl net.ipv4.conf.all.log_martians
/sbin/sysctl net.ipv4.conf.default.log_martians

echo '4.2.5 Enable Ignore Broadcast Requests (Scored)'
/sbin/sysctl net.ipv4.icmp_echo_ignore_broadcasts


echo '4.2.6 Enable Bad Error Message Protection (Scored)'
/sbin/sysctl net.ipv4.icmp_ignore_bogus_error_responses


echo '4.2.7 Enable RFC-recommended Source Route Validation (Scored)'
/sbin/sysctl net.ipv4.conf.all.rp_filter
/sbin/sysctl net.ipv4.conf.default.rp_filter

echo '4.2.8 Enable TCP SYN Cookies (Scored)'
/sbin/sysctl net.ipv4.tcp_syncookies

echo '4.5.5 Verify Permissions on /etc/hosts.deny (Scored)'
ls -l /etc/hosts.deny


echo '4.7 Enable firewalld (Scored)'
systemctl is-enabled firewalld


echo '5.1.1 Install the rsyslog package (Scored)'
rpm -q rsyslog


echo '5.1.2 Activate the rsyslog Service (Scored)'
systemctl is-enabled rsyslog

echo '5.1.4 Create and Set Permissions on rsyslog Log Files (Scored) (ALTERNATIVE)'
cat /etc/rsyslog.conf | grep -ve '^#' | grep -ve '^\s*$' | grep -ve '^\$'
find /var/log/ -type f -ls

echo '5.1.5 Configure rsyslog to Send Logs to a Remote Log Host (Scored)'
grep "^*.*[^I][^I]*@" /etc/rsyslog.conf


echo '5.2.1.3 Keep All Auditing Information (Scored)'
grep max_log_file_action /etc/audit/auditd.conf


echo '5.2.2 Enable auditd Service (Scored)'
systemctl is-enabled auditd

echo '5.2.3 Enable Auditing for Processes That Start Prior to auditd (Scored)'
grep "linux" /boot/grub2/grub.cfg

echo '5.2.4 Record Events That Modify Date and Time Information (Scored)'
grep time-change /etc/audit/audit.rules

echo '5.2.4 Record Events That Modify Date and Time Information (Scored) (ALTERNATIVE)'
grep -Hir time-change /etc/audit/*

echo '5.2.5 Record Events That Modify User/Group Information (Scored)'
grep identity /etc/audit/audit.rules

echo '5.2.5 Record Events That Modify User/Group Information (Scored) (ALTERNATIVE)'
grep -Hir identity /etc/audit/*

echo '5.2.6 Record Events That Modify the Systems Network Environment (Scored)'
grep system-locale /etc/audit/audit.rules

echo '5.2.6 Record Events That Modify the Systems Network Environment (Scored) (ALTERNATIVE)'
grep -Hir system-locale /etc/audit/*

echo '5.2.7 Record Events That Modify the Systems Mandatory Access Controls (Scored)'
grep MAC-policy /etc/audit/audit.rules

echo '5.2.7 Record Events That Modify the Systems Mandatory Access Controls (Scored) (ALTERNATIVE)'
grep -Hir MAC-policy /etc/audit/*

echo '5.2.8 Collect Login and Logout Events (Scored)'
grep logins /etc/audit/audit.rules

echo '5.2.8 Collect Login and Logout Events (Scored) (ALTERNATIVE)'
grep -Hir logins /etc/audit/*

echo '5.2.9 Collect Session Initiation Information (Scored)'
grep session /etc/audit/audit.rules

echo '5.2.9 Collect Session Initiation Information (Scored) (ALTERNATIVE)'
grep -Hir session /etc/audit/*

echo '5.2.10 Collect Discretionary Access Control Permission Modification Events (Scored)'
grep perm_mod /etc/audit/audit.rules

echo '5.2.10 Collect Discretionary Access Control Permission Modification Events (Scored) (ALTERNATIVE)'
grep -Hir perm_mod /etc/audit/*

echo '5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files (Scored)'
grep access /etc/audit/audit.rules

echo '5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files (Scored) (ALTERNATIVE)'
grep -Hir access /etc/audit/*

echo '5.2.12 Collect Use of Privileged Commands (Scored)'
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec grep -Hir {} /etc/audit/* \;

echo '5.2.13 Collect Successful File System Mounts (Scored)'
grep mounts /etc/audit/audit.rules


echo '5.2.14 Collect File Deletion Events by User (Scored)'
grep delete /etc/audit/audit.rules


echo '5.2.15 Collect Changes to System Administration Scope (sudoers) (Scored)'
grep scope /etc/audit/audit.rules


echo '5.2.16 Collect System Administrator Actions (sudolog) (Scored)'
grep actions /etc/audit/audit.rules

echo '5.2.17 Collect Kernel Module Loading and Unloading (Scored)'
grep modules /etc/audit/audit.rules


echo '5.2.18 Make the Audit Configuration Immutable (Scored)'
grep "^-e 2" /etc/audit/audit.rules


echo '6.1.1 Enable anacron Daemon (Scored)'
rpm -q cronie-anacron


echo '6.1.2 Enable crond Daemon (Scored)'
systemctl is-enabled crond

echo '6.1.3 Set User/Group Owner and Permission on /etc/anacrontab (Scored)'
stat -L -c "%a %u %g" /etc/anacrontab | egrep ".00 0 0"


echo '6.1.4 Set User/Group Owner and Permission on /etc/crontab (Scored)'
stat -L -c "%a %u %g" /etc/crontab | egrep ".00 0 0"

echo '6.1.5 Set User/Group Owner and Permission on /etc/cron.hourly (Scored)'
stat -L -c "%a %u %g" /etc/cron.hourly | egrep ".00 0 0"

echo '6.1.6 Set User/Group Owner and Permission on /etc/cron.daily (Scored)'
stat -L -c "%a %u %g" /etc/cron.daily | egrep ".00 0 0"

echo '6.1.7 Set User/Group Owner and Permission on /etc/cron.weekly (Scored)'
stat -L -c "%a %u %g" /etc/cron.weekly | egrep ".00 0 0"

echo '6.1.8 Set User/Group Owner and Permission on /etc/cron.monthly (Scored)'
stat -L -c "%a %u %g" /etc/cron.monthly | egrep ".00 0 0"

echo '6.1.9 Set User/Group Owner and Permission on /etc/cron.d (Scored)'
stat -L -c "%a %u %g" /etc/cron.d | egrep ".00 0 0"

echo '6.1.10 Restrict at Daemon (Scored)'
stat -L /etc/at.deny > /dev/null
stat -L -c "%a %u %g" /etc/at.allow | egrep ".00 0 0"

echo '6.1.11 Restrict at/cron to Authorized Users (Scored)'
ls -l /etc/cron.deny
ls -l /etc/at.deny
ls -l /etc/cron.allow
ls -l /etc/at.allow

echo '6.2.1 Set SSH Protocol to 2 (Scored)'
grep "^Protocol" /etc/ssh/sshd_config

echo '6.2.2 Set LogLevel to INFO (Scored)'
grep "^LogLevel" /etc/ssh/sshd_config

echo '6.2.3 Set Permissions on /etc/ssh/sshd_config (Scored)'
ls -l /etc/ssh/sshd_config

echo '6.2.4 Disable SSH X11 Forwarding (Scored)'
grep "^X11Forwarding" /etc/ssh/sshd_config

echo '6.2.5 Set SSH MaxAuthTries to 4 or Less (Scored)'
grep "^MaxAuthTries" /etc/ssh/sshd_config

echo '6.2.6 Set SSH IgnoreRhosts to Yes (Scored)'
grep "^IgnoreRhosts" /etc/ssh/sshd_config

echo '6.2.7 Set SSH HostbasedAuthentication to No (Scored)'
grep "^HostbasedAuthentication" /etc/ssh/sshd_config

echo '6.2.8 Disable SSH Root Login (Scored)'
grep "^PermitRootLogin" /etc/ssh/sshd_config

echo '6.2.9 Set SSH PermitEmptyPasswords to No (Scored)'
grep "^PermitEmptyPasswords" /etc/ssh/sshd_config

echo '6.2.10 Do Not Allow Users to Set Environment Options (Scored)'
grep PermitUserEnvironment /etc/ssh/sshd_config

echo '6.2.11 Use Only Approved Cipher in Counter Mode (Scored)'
grep "Ciphers" /etc/ssh/sshd_config

echo '6.2.12 Set Idle Timeout Interval for User Login (Scored)'
grep "^ClientAliveInterval" /etc/ssh/sshd_config
grep "^ClientAliveCountMax" /etc/ssh/sshd_config

echo '6.2.13 Limit Access via SSH (Scored)'
grep "^AllowUsers" /etc/ssh/sshd_config
grep "^AllowGroups" /etc/ssh/sshd_config
grep "^DenyUsers" /etc/ssh/sshd_config
grep "^DenyGroups" /etc/ssh/sshd_config

echo '6.2.14 Set SSH Banner (Scored)'
grep "^Banner" /etc/ssh/sshd_config

echo '6.3.1 Upgrade Password Hashing Algorithm to SHA-512 (Scored)'
authconfig --test | grep hashing | grep sha512

echo '6.3.2 Set Password Creation Requirement Parameters Using pam_cracklib (Scored)'
grep pam_cracklib.so /etc/pam.d/system-auth

echo '6.3.4 Limit Password Reuse (Scored)'
grep "remember" /etc/pam.d/system-auth

echo '6.5 Restrict Access to the su Command (Scored)'
grep pam_wheel.so /etc/pam.d/su
grep wheel /etc/group

echo '7.1.1 Set Password Expiration Days (Scored)'
grep PASS_MAX_DAYS /etc/login.defs
chage --list root

echo '7.1.2 Set Password Change Minimum Number of Days (Scored)'
grep PASS_MIN_DAYS /etc/login.defs
chage --list root
echo '7.1.3 Set Password Expiring Warning Days (Scored)'
grep PASS_WARN_AGE /etc/login.defs

echo '7.2 Disable System Accounts (Scored)'
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin") {print}'

echo '7.3 Set Default Group for root Account (Scored)'
grep "^root:" /etc/passwd | cut -f4 -d:

echo '7.4 Set Default umask for Users (Scored)'
grep "^umask 077" /etc/bashrc
grep "^umask 077" /etc/profile.d/*

echo '7.5 Lock Inactive User Accounts (Scored)'
useradd -D | grep INACTIVE

echo '8.1 Set Warning Banner for Standard Login Services (Scored)'
ls -l /etc/motd
ls /etc/issue
ls /etc/issue.net

echo '8.2 Remove OS Information from Login Warning Banners (Scored)'
egrep '(\\v|\\r|\\m|\\s)' /etc/issue
egrep '(\\v|\\r|\\m|\\s)' /etc/motd
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net

echo '9.1.2 Verify Permissions on /etc/passwd (Scored)'
ls -l /etc/passwd

echo '9.1.3 Verify Permissions on /etc/shadow (Scored)'
ls -l /etc/shadow

echo '9.1.4 Verify Permissions on /etc/gshadow (Scored)'
ls -l /etc/gshadow

echo '9.1.5 Verify Permissions on /etc/group (Scored)'
ls -l /etc/group

echo '9.1.6 Verify User/Group Ownership on /etc/passwd (Scored)'
ls -l /etc/passwd

echo '9.1.7 Verify User/Group Ownership on /etc/shadow (Scored)'
ls -l /etc/shadow

echo '9.1.8 Verify User/Group Ownership on /etc/gshadow (Scored)'
ls -l /etc/gshadow

echo '9.1.9 Verify User/Group Ownership on /etc/group (Scored)'
ls -l /etc/group

echo '9.1.11 Find Un-owned Files and Directories (Scored)'
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls

echo '9.1.12 Find Un-grouped Files and Directories (Scored)'
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls

echo '9.2.1 Ensure Password Fields are Not Empty (Scored)'
cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}'

echo '9.2.2 Verify No Legacy "+" Entries Exist in /etc/passwd File (Scored)'
grep '^+:' /etc/passwd

echo '9.2.3 Verify No Legacy "+" Entries Exist in /etc/shadow File (Scored)'
grep '^+:' /etc/shadow

echo '9.2.4 Verify No Legacy "+" Entries Exist in /etc/group File (Scored)'
grep '^+:' /etc/group

echo '9.2.5 Verify No UID 0 Accounts Exist Other Than root (Scored)'
cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }'

echo '9.2.6 Ensure root PATH Integrity (Scored)'
if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
	echo "Empty Directory in PATH (::)" 
fi
if [ "`echo $PATH | /bin/grep :$`" != "" ]; then
	echo "Trailing : in PATH" 
fi
p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'` 
set -- $p
while [ "$1" != "" ]; do
	if [ "$1" = "." ]; then 
		echo "PATH contains ." 
		shift
		continue
	fi
	if [ -d $1 ]; then
		dirperm=`ls -ldH $1 | /bin/cut -f1 -d" "`
		if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
			echo "Group Write permission set on directory $1" 
		fi
		if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
			echo "Other Write permission set on directory $1"
		fi
			dirown=`ls -ldH $1 | awk '{print $3}'`
			if [ "$dirown" != "root" ] ; then 
				echo $1 is not owned by root
			fi 
	else
			echo $1 is not a directory
		fi
	   shift
done

echo '9.2.7 Check Permissions on User Home Directories (Scored)'
for dir in `cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
  /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do 
	dirperm=`ls -ld $dir | /bin/cut -f1 -d" "`
	if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
		echo "Group Write permission set on directory $dir"
	fi
	if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
		echo "Other Read permission set on directory $dir" 
	fi
	if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
		echo "Other Write permission set on directory $dir" 
	fi
	if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
		echo "Other Execute permission set on directory $dir" 
	fi
done

echo '9.2.8 Check User Dot File Permissions (Scored)'
for dir in `cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' | 
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
	for file in $dir/.[A-Za-z0-9]*; do
		if [ ! -h "$file" -a -f "$file" ]; then 
			fileperm=`ls -ld $file | /bin/cut -f1 -d" "`
			if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
			echo "Group Write permission set on file $file" 
			fi
			if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
			echo "Other Write permission set on file $file" 
			fi
		fi 
	done
done

echo '9.2.9 Check Permissions on User .netrc Files (Scored)'
for dir in `cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
  /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do 
  for file in $dir/.netrc; do
	if [ ! -h "$file" -a -f "$file" ]; then 
		fileperm=`ls -ld $file | /bin/cut -f1 -d" "` 
		if [ `echo $fileperm | /bin/cut -c5 ` != "-" ] 
			then
				echo "Group Read set on $file"
	fi 
	if [ `echo $fileperm | /bin/cut -c6 ` !="-" ]
	then 
			echo "Group Write set on $file"
	fi 
	if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
	then
			echo "Group Execute set on $file"
	fi 
	if [`echo $fileperm | /bin/cut -c8 ` != "-" ]
	then
			echo "Other Read set on $file"
	fi
	if [`echo $fileperm | /bin/cut -c9 ` != "-" ] 
	then
			echo "Other Write set on $file"
	fi
	if [`echo $fileperm | /bin/cut -c10 ` != "-" ]
	then
			echo "Other Execute set on $file"
	fi
   fi
  done
done

echo '9.2.10 Check for Presence of User .rhosts Files (Scored)'
for dir in `cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
	/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do 
	for file in $dir/.rhosts; do
		if [ ! -h "$file" -a -f "$file" ]; then 
			echo ".rhosts file in $dir"
		fi 	done
done

echo '9.2.11 Check Groups in /etc/passwd (Scored)'
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
grep -q -P "^.*?:x:$i:" /etc/group
if [ $? -ne 0 ]; then
	echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" 
fi
done

echo '9.2.12 Check That Users Are Assigned Valid Home Directories (Scored)'
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do 
if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
	echo "The home directory ($dir) of user $user does not exist."
fi
done

echo '9.2.13 Check User Home Directory Ownership (Scored)'
cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then owner=$(stat -L -c "%U" "$dir")
	if [ "$owner" != "$user" ]; then
		echo "The home directory ($dir) of user $user is owned by $owner."
	fi
fi
done

echo '9.2.14 Check for Duplicate UIDs (Scored)'
cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
	while read x ; do
	[ -z "${x}" ] && break 
	set - $x
	if [ $1 -gt 1 ]; then
		users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \ 
			/etc/passwd | /usr/bin/xargs`
		echo "Duplicate UID ($2): ${users}" 
	fi
done

echo '9.2.15 Check for Duplicate GIDs (Scored)'
cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
	while read x ; do
	[ -z "${x}" ] && break
	set - $x
	if [ $1 -gt 1 ]; then
		grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
			/etc/group | xargs`
		echo "Duplicate GID ($2): ${grps}"
	fi 
done

echo '9.2.16 Check That Reserved UIDs Are Assigned to System Accounts (Scored)'
defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"
cat /etc/passwd |\
/bin/awk -F: '($3 < 500) { print $1" "$3 }' |\
while read user uid; do
	found=0
	for tUser in ${defUsers}
	do
		if [ ${user} = ${tUser} ]; then
			found=1 
		fi
	done
	if [ $found -eq 0 ]; then
		echo "User $user has a reserved UID ($uid)." 
	fi
done

echo '9.2.17 Check for Duplicate User Names (Scored)'
cat /etc/passwd | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
	while read x ; do
	[ -z "${x}" ] && break 
	set - $x
	if [ $1 -gt 1 ]; then
		uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
			 /etc/passwd | xargs`
		echo "Duplicate User Name ($2): ${uids}" 
	fi
done

echo '9.2.18 Check for Duplicate Group Names (Scored)'
cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
	while read x ; do
	[ -z "${x}" ] && break 
	set - $x
	if [ $1 -gt 1 ]; then
		gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
			/etc/group | xargs`
		echo "Duplicate Group Name ($2): ${gids}"
	fi 
done

echo '9.2.19 Check for Presence of User .netrc Files (Scored)'
for dir in `cat /etc/passwd |\
	/bin/awk -F: '{ print $6 }'`; do
	if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
		echo ".netrc file $dir/.netrc exists" 
	fi
done

echo '9.2.20 Check for Presence of User .forward Files (Scored)'
for dir in `cat /etc/passwd |\
	/bin/awk -F: '{ print $6 }'`; do
	if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then 
		echo ".forward file $dir/.forward exists"
	fi
done
