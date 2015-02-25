#!/bin/env python
# -*- coding: utf-8 -*-

"""
  RHEL 7 hardenings check
  Should possible work on Fedora and CentOS too....

 Copyright Jan-Karel Visser - all rights are reserved
 Licensed under the LGPLv3 (http://www.gnu.org/licenses/lgpl.html)

 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

"""



import subprocess as sub



results=[]
opmerkingen = []

def opdracht(cmdDict):
    for item in cmdDict:
        cmd = cmdDict[item]["cmd"]
        out, error = sub.Popen([cmd], stdout=sub.PIPE, stderr=sub.PIPE, shell=True).communicate()
        results = out.split('\n')
        cmdDict[item]["results"]=results
    return cmdDict

def uitvoer(cmdDict):
    for item in cmdDict:
        msg = cmdDict[item]["msg"]
        results = cmdDict[item]["results"]
        opdracht = cmdDict[item]["cmd"]
        check = cmdDict[item]["check"]
        ret = cmdDict[item]["ret"]

        opdracht = cmdDict[item]["cmd"]
        if check == 1:
            if ret:
                if results.find(ret) >=1:
                  ditisgoed = True
                else:
                  opmerkingen.append(cmdDict[item])

            else:
                if results[0] =='':
                  opmerkingen.append(cmdDict[item])
        else:
            print "\n[+] " + msg
            print "opdracht: " + str(opdracht) + "\n"
            for result in results:

                if result.strip() != "":
                  print "    " + result.strip()



#Basis databees


"""
Opdrachten

"""







log = {"DMESG":{"cmd":"cat /var/log/dmesg","msg":"DMESG (Display message / driver message)","results":results,"check":False,"ret":False,"comment":False}, 
      "SECURE":{"cmd":"cat /var/log/secure","msg":"SECURE","results":results,"check":False,"ret":False,"comment":False},
      "AIDE":{"cmd":"cat /var/log/aide/aide.log","msg":"AIDE (Advanced Intrusion Detection Environment)","results":results,"check":False,"ret":False,"comment":False},
      "MAILLOG":{"cmd":"cat /var/log/maillog","msg":"Maillog","results":results,"check":False,"ret":False,"comment":False},
      }

systeeminformatie = {"OS":{"cmd":"cat /etc/redhat-release","msg":"Operating System","results":results,"check":False,"ret":False,"comment":False}, 
       "KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":results,"check":False,"ret":False,"comment":False}, 
       "HOSTNAME":{"cmd":"hostname", "msg":"Hostname", "results":results,"check":False,"ret":False,"comment":False},
       "MEMINFO":{"cmd":"cat /proc/meminfo", "msg":"Geheugen informatie", "results":results,"check":False,"ret":False,"comment":False},
       "MEMINFO2":{"cmd":"free -m", "msg":"Geheugen gebruik", "results":results,"check":False,"ret":False,"comment":False},
       "DMIDECODE":{"cmd":"dmidecode", "msg":"BIOS informatie", "results":results,"check":False,"ret":False,"comment":False}
      }

netwerkinformatie = {"NETINFO":{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces", "results":results,"check":False,"ret":False,"comment":False},
       "ROUTE":{"cmd":"route", "msg":"Route", "results":results,"check":False,"ret":False,"comment":False},
       "NETSTAT":{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat", "results":results,"check":False,"ret":False,"comment":False},
       "ARP":{"cmd":"arp", "msg":"Arp", "results":results,"check":False,"ret":False,"comment":False}
      }

gebruikersinformatie = {"WHOAMI":{"cmd":"whoami", "msg":"Huidige gebruiker", "results":results,"check":False,"ret":False,"comment":False},
        "ID":{"cmd":"id","msg":"Huidige gebruikers id", "results":results,"check":False,"ret":False,"comment":False},
        "ALLUSERS":{"cmd":"cat /etc/passwd", "msg":"Alle gebruikers", "results":results,"check":False,"ret":False,"comment":False},
        "SUPUSERS":{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Super users gevonden:", "results":results,"check":False,"ret":False,"comment":False},
        "HISTORY":{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Root en huidige gebruiker history (afhankelijk  van privilege)", "results":results,"check":False,"ret":False,"comment":False},
        "ENV":{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Omgeving", "results":results,"check":False,"ret":False,"comment":False},
        "SUDOERS":{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (privileged)", "results":results,"check":False,"ret":False,"comment":False},
        "LOGGEDIN":{"cmd":"w 2>/dev/null", "msg":"Aangemelde gebruikers", "results":results,"check":False,"ret":False,"comment":False},
        "LAST":{"cmd":"last", "msg":"Login geschiedenis", "results":results,"check":False,"ret":False,"comment":False},
        "LASTLOG":{"cmd":"lastlog", "msg":"Uitvoer lastlog", "results":results,"check":False,"ret":False,"comment":False},
       }

crontaken = {"CRON":{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"Actieve cron taken", "results":results,"check":False,"ret":False,"comment":False},
        "CRONW": {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Schrijfbare cron directories", "results":results,"check":False,"ret":False,"comment":False}
       }  

schijfinformatie = {
        "DFH":{"cmd":"df -h","msg":"Schijf gebruik", "results":results,"check":False,"ret":False,"comment":False},
        "MOUNT":{"cmd":"mount","msg":"Mount resultaat", "results":results,"check":False,"ret":False,"comment":False},
         "FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab (file systems table)", "results":results,"check":False,"ret":False,"comment":False},
         "SEPARATE":{"cmd":'grep "[[:space:]]/tmp[[:space:]]" /etc/fstab', "msg":"1.1.1 Create Separate Partition for /tmp (Scored)", "results":results,"check":1,"ret":False,
"comment":['The /tmp directory is a world-writable directory used for temporary storage by all usersand some applications.',
'Since the /tmp directory is intended to be world-writable, there is a risk of resource exhaustion if it is not bound to a separate partition']},
"NODEV":{"cmd":'grep "[[:space:]]/tmp[[:space:]]" /etc/fstab', "msg":"1.1.2 Set nodev option for /tmp Partition (Scored)", "results":results,"check":1,"ret":False,"comment":['The nodev mount option specifies that the filesystem cannot contain special devices.',
'Since the /tmp filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices in /tmp.']},
"NOSUID1":{"cmd":'[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nosuid', "msg":"1.1.3 Set nosuid option for /tmp Partition (Scored)", "results":results,"check":1,"ret":False,"comment":['False','']},
"NOSUID2":{"cmd":'mount | grep "[[:space:]]/tmp[[:space:]] | grep nosuid', "msg":"1.1.3 Set nosuid option for /tmp Partition (Scored)", "results":results,"check":1,"ret":False,"comment":['False','']},
        "NOEXEC1":{"cmd":'grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep noexec', "msg":"1.1.4 Set noexec option for /tmp Partition (Scored)", "results":results,"check":1,"ret":False,
"comment":['The noexec mount option specifies that the filesystem cannot contain executable binaries.',
'Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /tmp.']},

"NOEXEC2":{"cmd":'mount | grep "[[:space:]]/tmp[[:space:]]" | grep noexec', "msg":"1.1.4 Set noexec option for /tmp Partition (Scored)", "results":results,"check":1,"ret":False,
"comment":['The noexec mount option specifies that the filesystem cannot contain executable binaries.',
'Since the /tmp filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from /tmp.']},

"SEPVAR":{"cmd":'grep "[[:space:]]/var[[:space:]]" /etc/fstab', "msg":"1.1.5 Create Separate Partition for /var (Scored)", "results":results,"check":1,"ret":False,
"comment":['The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable',
'Since the /var directory may contain world-writable files and directories, there is a risk of resource exhaustion if it is not bound to a separate partition.']},

"BINDVAR1":{"cmd":'grep -e "^/tmp[[:space:]]" /etc/fstab | grep /var/tmp', "msg":"1.1.6 Bind Mount the /var/tmp directory to /tmp (Scored)", "results":results,"check":1,"ret":False,
"comment":['The /var/tmp directory is normally a standalone directory in the /var file system. Binding /var/tmp to /tmp establishes an unbreakable link to /tmp that cannot be removed (even by the root user). ',
'All programs that use /var/tmp and /tmp to read/write temporary files will always be written to the /tmp file system, preventing a user from running the /var file system out of space or trying to perform operations that have been blocked in the /tmp filesystem.']},

"BINDVAR2":{"cmd":'mount | grep -e "^/tmp[[:space:]]" | grep /var/tmp', "msg":"1.1.6 Bind Mount the /var/tmp directory to /tmp (Scored)", "results":results,"check":1,"ret":False,
"comment":['The /var/tmp directory is normally a standalone directory in the /var file system. Binding /var/tmp to /tmp establishes an unbreakable link to /tmp that cannot be removed (even by the root user). ',
'All programs that use /var/tmp and /tmp to read/write temporary files will always be written to the /tmp file system, preventing a user from running the /var file system out of space or trying to perform operations that have been blocked in the /tmp filesystem.']},


"SEPLOG":{"cmd":'grep "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab', "msg":"1.1.8 Create Separate Partition for /var/log/audit (Scored)", "results":results,"check":1,"ret":False,
"comment":['The auditing daemon, auditd, stores log data in the /var/log/audit directory.',
'There are two important reasons to ensure that data gathered by auditd is stored on a separate partition: protection against resource exhaustion (since the audit.log file can grow quite large) and protection of audit data. ']},


"SEPHOME":{"cmd":'grep "[[:space:]]/home[[:space:]]" /etc/fstab', "msg":"1.1.9 Create Separate Partition for /home (Scored)", "results":results,"check":1,"ret":False,
"comment":['The /home directory is used to support disk storage needs of local users',
'If the system is intended to support local users, create a separate partition for the /home directory to protect against resource exhaustion and restrict the type of files that can be stored under /home.']},

"HOMENODEV":{"cmd":'grep "[[:space:]]/home[[:space:]]" /etc/fstab', "msg":"1.1.10 Add nodev Option to /home (Scored)", "results":results,"check":1,"ret":False,
"comment":['When set on a file system, this option prevents character and block special devices from being defined, or if they exist, from being used as character and block special devices.',
'Since the user partitions are not intended to support devices, set this option to ensure that users cannot attempt to create block or character special devices.']},

"SHMNODEV":{"cmd":'grep /dev/shm /etc/fstab | grep nodev', "msg":"1.1.14 Add nodev Option to /dev/shm Partition (Scored)", "results":results,"check":1,"ret":False,
"comment":['The nodev mount option specifies that the /dev/shm (temporary filesystem stored in memory) cannot contain block or character special devices.',
'Since the /dev/shm filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in /dev/shm partitions']},

"SHMNOSUID":{"cmd":'grep /dev/shm /etc/fstab | grep nodev', "msg":"1.1.15 Add nosuid Option to /dev/shm Partition (Scored)", "results":results,"check":1,"ret":False,
"comment":['The nosuid mount option specifies that the /dev/shm (temporary filesystem stored in memory) will not execute setuid and setgid on executable programs as such, but rather execute them with the uid and gid of the user executing the program.',
'Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them']},

"SHMNOEXEC":{"cmd":'grep /dev/shm /etc/fstab | grep nodev', "msg":"1.1.16 Add noexec Option to /dev/shm Partition (Scored)", "results":results,"check":1,"ret":False,
"comment":['Set noexec on the shared memory partition to prevent programs from executing from there.',
'Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system.']},

"STICKBIT":{"cmd":"df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d  \ ( -perm -0002 -a ! -perm -1000 \) 2>/dev/null", "msg":"1.1.17 Set Sticky Bit on All World-Writable Directories (Scored)", "results":results,"check":1,"ret":False,
"comment":['Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.',
'This feature prevents the ability to delete or rename files in world writable directories (such as /tmp) that are owned by another user.']},


        }


permissies = {"WWDIRSROOT":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"World Writeable Directories voor gebruiker/groep 'Root'", "results":results,"check":False,"ret":False,"comment":False},
       "WWDIRS":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg":"World Writeable Directories voor gebruiker anders dan 'Root'", "results":results,"check":False,"ret":False,"comment":False},
       "WWFILES":{"cmd":"find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null", "msg":"World Writable Bestanden", "results":results,"check":False,"ret":False,"comment":False},
       "SUID":{"cmd":"find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null", "msg":"SUID/SGID Bestanden", "results":results,"check":False,"ret":False,"comment":False},
       "ROOTHOME":{"cmd":"ls -ahlR /root 2>/dev/null", "msg":"Controle op toegangelijkheid rootfolder", "results":results,"check":False,"ret":False,"comment":False}
      }

tools = {"TOOLS":{"cmd":"which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null", "msg":"Aangetroffen tools", "results":results,"check":False,"ret":False,"comment":['Een kwaadwillende kan met het aanroepen','Dezebevinding dient handmatig verder worden uitgewert']},

"RHELGPG":{"cmd":'rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey' , "msg":"1.2.2 Verify Red Hat GPG Key is Installed (Scored)", "results":results,"check":1,"ret":False,
"comment":['Red Hat cryptographically signs updates with a GPG key to verify that they are valid.',
'It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system.']},

"RHELGPGCHECK":{"cmd":'rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey' , "msg":"1.2.3 Verify that gpgcheck is Globally Activated (Scored)", "results":results,"check":1,"ret":'gpg(Red Hat, Inc.',
"comment":['The gpgcheck option, found in the main section of the /etc/yum.conf file determines if an RPM package\'s signature is always checked prior to its installation.',
'It is important to ensure that an RPM\'s package signature is always checked prior to installation to ensure that the software is obtained from a trusted source.']},
"SOFTPAKKET": {"cmd": "rpm -qVa | awk '$2 != \"c\" { print $0}'", "msg": "Pakket integriteit", "results":results,"check":False,"ret":False,"comment":False}

}

 #pakket integriteit
 #"rpm -qVa | awk '$2 != \"c\" { print $0}'"
 #rpm -q aide ret=aide-

selinux = {
"SECONFIG": {"cmd":"cat /etc/selinux/config", "msg": "SELinux configuratie", "results":results,"check":False,"ret":False,"comment":False},
"SECRUN": {"cmd":"usr/sbin/sestatus","msg": "SELinux sestatus opdracht", "results":results,"check":False,"ret":False,"comment":False},
"RPMTROUBLE": {"cmd":"rpm -q setroubleshoot","msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":'is not installed',"comment":False},
"SADEAMONS": {"cmd":"ps -eZ | egrep \"initrc\" | egrep -vw \"tr|ps|egrep|bash|awk\" | tr ':' ' ' | awk '{print $NF }'","msg": "Onbevestigde deamons",
"results":results,"check":1,"ret":False,"comment":['Deamons die niet zijn gedefineerd in de SELinux police erven de rechten van het parent proces', 
'Omdat de deamons worden gestart door het proces init, erven de processen de rechten over van initrc_t. Het gevolg hiervan is dat processen kunnen draaien met meer rechten dan noodzakelijk']},

"RPMTROUBLE2": {"cmd":"rpm -q mcstrans","msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":'is not installed',"comment":False},

"GRUB1": {"cmd":'stat -L -c "%u %g" /boot/grub2/grub.cfg | egrep "0 0"',"msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":'0 0',"comment":False},

"GRUB2": {"cmd":'stat -L -c "%a" /boot/grub2/grub.cfg | egrep ".00"',"msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":False,"comment":False},
"SECLIMITS": {"cmd":'grep "hard core" /etc/security/limits.conf',"msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":'* hard core 0',"comment":False},
#sysctl fs.suid_dumpable

}


print "=== Systeem informatie:\n"
systeeminformatie = opdracht(systeeminformatie)
uitvoer(systeeminformatie)
print "\n\n=== Netwerk informatie:\n"
netwerkinformatie = opdracht(netwerkinformatie)
uitvoer(netwerkinformatie)
print "\n\n=== Schijf & partitie informatie:\n"
schijfinformatie = opdracht(schijfinformatie)
uitvoer(schijfinformatie)
print "\n\n=== Cronjobs:\n"
crontaken = opdracht(crontaken)
uitvoer(crontaken)
print "\n\n=== Gebruikers informatie:\n"
gebruikersinformatie = opdracht(gebruikersinformatie)
uitvoer(gebruikersinformatie)
print "\n\n=== Permissies:\n"
permissies = opdracht(permissies)
uitvoer(permissies)
print "\n\n=== Hardening:\n"
selinux = opdracht(selinux)
uitvoer(selinux)
print "\n\n=== Software:\n"
tools = opdracht(tools)
uitvoer(tools)
print "\n\n=== Log bestanden:\n"
log = opdracht(log)
uitvoer(log)

print "\n\n=== Conclusie: \nDe volgende "+str(len(opmerkingen))+" punten wijken af met betrekking tot de best practices voor hardening:"

#volgorde omdraaien
for x in opmerkingen:
    print '\n'+x['msg'] + '\nAudit:'+ x['cmd'] + '\n\nToelichting:\n'+ x['comment'][0] +'\n\nRisico:\n'+ x['comment'][1]


