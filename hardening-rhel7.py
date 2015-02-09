#!/bin/env python
# -*- coding: utf-8 -*-

"""
 Hardenings check

 Based on STIG and CIS

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
	    print "[+] " + msg
        print "opdracht: " + str(opdracht)
        opdracht = cmdDict[item]["cmd"]
        if check:
        	if ret:

        	else:

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
	     "FSTAB":{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab entries", "results":results,"check":False,"ret":False,"comment":False}
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

print "Basis informatie:\n"
print "=== Systeem informatie:\n"
systeeminformatie = opdracht(systeeminformatie)
uitvoer(systeeminformatie)
print "=== Netwerkinformatie:\n"
netwerkinformatie = opdracht(netwerkinformatie)
uitvoer(netwerkinformatie)
print "=== Schijfinformatie:\n"
schijfinformatie = opdracht(schijfinformatie)
"""
#1.1.1 Create Separate Partition for /tmp (Scored)
'grep "[[:space:]]/tmp[[:space:]]" /etc/fstab'
#1.1.2 Set nodev option for /tmp Partition (Scored)
'grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nodev'
mount | grep "[[:space:]]/tmp[[:space:]]" | grep nodev 
#1.1.3 Set nosuid option for /tmp Partition (Scored)
'grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nosuid'
'mount | grep "[[:space:]]/tmp[[:space:]]" | grep nosuid' 
"""

uitvoer(schijfinformatie)
print "=== Cronjobs:\n"
crontaken = opdracht(crontaken)
uitvoer(crontaken)
print "=== Gebruikersinformatie:\n"
gebruikersinformatie = opdracht(gebruikersinformatie)
uitvoer(gebruikersinformatie)
print "=== Permissies:\n"
permissies = opdracht(permissies)
uitvoer(permissies)
print "=== Aanwezige tools:\n"
tools = opdracht(tools)
uitvoer(tools)

print "=== Benchmark:\n"


