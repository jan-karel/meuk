#!/bin/env python
# -*- coding: utf-8 -*-

"""
 Hardenings check

 Based on STIG and CIS RHEL7 benchmark

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
                    opmerkingen.append(cmdDict[item])

            else:
                if results[0] =='':
                    opmerkingen.append(cmdDict[item])
        else:
            print "\n[+] " + msg
            print "command: " + str(opdracht) + "\n"
            for result in results:

                if result.strip() != "":
                    print "    " + result.strip()



# Basic system info


"""
Opdrachten

"""


systeeminformatie = {"OS":{"cmd":"cat /etc/issue","msg":"Operating System","results":results,"check":False,"ret":False,"comment":False}, 
       "KERNEL":{"cmd":"cat /proc/version","msg":"Kernel","results":results,"check":False,"ret":False,"comment":False}, 
       "HOSTNAME":{"cmd":"hostname", "msg":"Hostname", "results":results,"check":False,"ret":False,"comment":False}
      }

netwerkinformatie = {"NETINFO":{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces", "results":results,"check":False,"ret":False,"comment":False},
       "ROUTE":{"cmd":"route", "msg":"Route", "results":results,"check":False,"ret":False,"comment":False},
       "NETSTAT":{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat", "results":results,"check":False,"ret":False,"comment":False}
      }

schijfinformatie = {"MOUNT":{"cmd":"mount","msg":"Mount results", "results":results,"check":False,"ret":False,"comment":False},
         "FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab entries", "results":results,"check":False,"ret":False,"comment":False},
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


# Scheduled Cron Jobs
crontaken = {"CRON":{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"Scheduled cron jobs", "results":results,"check":False,"ret":False,"comment":False},
        "CRONW": {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Writable cron dirs", "results":results,"check":False,"ret":False,"comment":False}
       }        

gebruikersinformatie = {"WHOAMI":{"cmd":"whoami", "msg":"Current User", "results":results,"check":False,"ret":False,"comment":False},
        "ID":{"cmd":"id","msg":"Current User ID", "results":results,"check":False,"ret":False,"comment":False},
        "ALLUSERS":{"cmd":"cat /etc/passwd", "msg":"All users", "results":results,"check":False,"ret":False,"comment":False},
        "SUPUSERS":{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Super Users Found:", "results":results,"check":False,"ret":False,"comment":False},
        "HISTORY":{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Root and current user history (depends on privs)", "results":results,"check":False,"ret":False,"comment":False},
        "ENV":{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Environment", "results":results,"check":False,"ret":False,"comment":False},
        "SUDOERS":{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (privileged)", "results":results,"check":False,"ret":False,"comment":False},
        "LOGGEDIN":{"cmd":"w 2>/dev/null", "msg":"Logged in User Activity", "results":results,"check":False,"ret":False,"comment":False}
       }

permissies = {"WWDIRSROOT":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"World Writeable Directories for User/Group 'Root'", "results":results,"check":False,"ret":False,"comment":False},
       "WWDIRS":{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg":"World Writeable Directories for Users other than Root", "results":results,"check":False,"ret":False,"comment":False},
       "WWFILES":{"cmd":"find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null", "msg":"World Writable Files", "results":results,"check":False,"ret":False,"comment":False},
       "SUID":{"cmd":"find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null", "msg":"SUID/SGID Files and Directories", "results":results,"check":False,"ret":False,"comment":False},
       "ROOTHOME":{"cmd":"ls -ahlR /root 2>/dev/null", "msg":"Checking if root's home folder is accessible", "results":results,"check":False,"ret":False,"comment":False}
      }

tools = {"TOOLS":{"cmd":"which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null", "msg":"Installed Tools", "results":results,"check":False,"ret":False,"comment":False}}


print "=== System information:\n"
systeeminformatie = opdracht(systeeminformatie)
uitvoer(systeeminformatie)
print "\n\n=== Network information:\n"
netwerkinformatie = opdracht(netwerkinformatie)
uitvoer(netwerkinformatie)
print "\n\n=== Disk & partition information:\n"
schijfinformatie = opdracht(schijfinformatie)
uitvoer(schijfinformatie)
print "\n\n=== Cronjobs:\n"
crontaken = opdracht(crontaken)
uitvoer(crontaken)
print "\n\n=== User information:\n"
gebruikersinformatie = opdracht(gebruikersinformatie)
uitvoer(gebruikersinformatie)
#print "\n\n=== Permissions:\n"
#permissies = opdracht(permissies)
#uitvoer(permissies)
print "\n\n=== Available tools:\n"
tools = opdracht(tools)
uitvoer(tools)

print "\n\n=== Conclusion \nThe following "+str(len(opmerkingen))+" points are inconsistent with the best practices for hardening"

#volgorde omdraaien
for x in opmerkingen:
    print '\n'+x['msg'] + '\nAudit:'+ x['cmd'] + '\n\nDescription:\n'+ x['comment'][0] +'\n\nRationale:\n'+ x['comment'][1]


