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
    for item in sorted(cmdDict):
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
                if results[0].find(ret) >=1:
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
"""
Opdrachten

"""

log = {1:{"cmd":"cat /var/log/dmesg","msg":"DMESG (Display message / driver message)","results":results,"check":False,"ret":False,"comment":False}, 
      2:{"cmd":"cat /var/log/secure","msg":"SECURE","results":results,"check":False,"ret":False,"comment":False},
      3:{"cmd":"cat /var/log/aide/aide.log","msg":"AIDE (Advanced Intrusion Detection Environment)","results":results,"check":False,"ret":False,"comment":False},
      4:{"cmd":"cat /var/log/maillog","msg":"Maillog","results":results,"check":False,"ret":False,"comment":False},
      }

systeeminformatie = {1:{"cmd":"cat /etc/redhat-release","msg":"Operating System","results":results,"check":False,"ret":False,"comment":False}, 
       2:{"cmd":"cat /proc/version","msg":"Kernel","results":results,"check":False,"ret":False,"comment":False}, 
       3:{"cmd":"hostname", "msg":"Hostname", "results":results,"check":False,"ret":False,"comment":False},
       4:{"cmd":"cat /proc/meminfo", "msg":"Geheugen informatie", "results":results,"check":False,"ret":False,"comment":False},
       5:{"cmd":"free -m", "msg":"Geheugen gebruik", "results":results,"check":False,"ret":False,"comment":False},
       6:{"cmd":"dmidecode", "msg":"BIOS informatie", "results":results,"check":False,"ret":False,"comment":False}
      }

netwerkinformatie = {1:{"cmd":"/sbin/ifconfig -a", "msg":"Interfaces", "results":results,"check":False,"ret":False,"comment":False},
       2:{"cmd":"route", "msg":"Route", "results":results,"check":False,"ret":False,"comment":False},
       3:{"cmd":"netstat -antup | grep -v 'TIME_WAIT'", "msg":"Netstat", "results":results,"check":False,"ret":False,"comment":False},
       4:{"cmd":"arp", "msg":"Arp", "results":results,"check":False,"ret":False,"comment":False}
      }

gebruikersinformatie = {1:{"cmd":"whoami", "msg":"Huidige gebruiker", "results":results,"check":False,"ret":False,"comment":False},
        2:{"cmd":"id","msg":"Huidige gebruikers id", "results":results,"check":False,"ret":False,"comment":False},
        3:{"cmd":"cat /etc/passwd", "msg":"Alle gebruikers", "results":results,"check":False,"ret":False,"comment":False},
        4:{"cmd":"grep -v -E '^#' /etc/passwd | awk -F: '$3 == 0{print $1}'", "msg":"Super users gevonden:", "results":results,"check":False,"ret":False,"comment":False},
        5:{"cmd":"ls -la ~/.*_history; ls -la /root/.*_history 2>/dev/null", "msg":"Root en huidige gebruiker history (afhankelijk  van privilege)", "results":results,"check":False,"ret":False,"comment":False},
        6:{"cmd":"env 2>/dev/null | grep -v 'LS_COLORS'", "msg":"Omgeving", "results":results,"check":False,"ret":False,"comment":False},
        7:{"cmd":"cat /etc/sudoers 2>/dev/null | grep -v '#' 2>/dev/null", "msg":"Sudoers (privileged)", "results":results,"check":False,"ret":False,"comment":False},
        8:{"cmd":"w 2>/dev/null", "msg":"Aangemelde gebruikers", "results":results,"check":False,"ret":False,"comment":False},
        9:{"cmd":"last", "msg":"Login geschiedenis", "results":results,"check":False,"ret":False,"comment":False},
        10:{"cmd":"lastlog", "msg":"Uitvoer lastlog", "results":results,"check":False,"ret":False,"comment":False},
       }

crontaken = {1:{"cmd":"ls -la /etc/cron* 2>/dev/null", "msg":"Actieve cron taken", "results":results,"check":False,"ret":False,"comment":False},
        2: {"cmd":"ls -aRl /etc/cron* 2>/dev/null | awk '$1 ~ /w.$/' 2>/dev/null", "msg":"Schrijfbare cron directories", "results":results,"check":False,"ret":False,"comment":False}
       }  

schijfinformatie = {
        1:{"cmd":"df -h","msg":"Schijf gebruik", "results":results,"check":False,"ret":False,"comment":False},
        2:{"cmd":"mount","msg":"Mount resultaat", "results":results,"check":False,"ret":False,"comment":False},
        3:{"cmd":"cat /etc/fstab 2>/dev/null", "msg":"fstab (file systems table)", "results":results,"check":False,"ret":False,"comment":False},
        4:{"cmd":'grep "[[:space:]]/tmp[[:space:]]" /etc/fstab', "msg":"Maak een aparte partitie voor tmp aan", "results":results,"check":1,"ret":False,
"comment":['De /tmp directorie is een world-writable directorie gebruikt voor tijdelijke opslag voor alle gebruikers en applicaties.',
'Omdat deze directory bedoeld world-writable is, is er een risico voor dat men het systeem kan laten vastlopen door de /tmp volledig te vullen.']},

        5:{"cmd":'grep "[[:space:]]/tmp[[:space:]]" /etc/fstab', "msg":"Zet de nodev optie voor de tmp partitie", "results":results,"check":1,"ret":False,"comment":['De nodev optie bepaalt dat de partitie geen special devices mag bevatten.',
'De /tmp directorie is niet bestemd voor devices, zet deze optie zodat gebruikers geen block of character special devices in /tmp kunnen aanmaken.']},
        
        6:{"cmd":'[[:space:]]/tmp[[:space:]]" /etc/fstab | grep nosuid', "msg":"Zet de nosuid optie voor de /tmp partitie", "results":results,"check":1,"ret":False,
"comment":['De nosuid mount optie zorgt dat gebruikers geen userid bestanden kunnen aanmaken','Omdat /tmp alleen bedoeld is voor tijdelijke opslag, zet deze optie zodat gebruikers geen userid bestanden in /tmp kunnen aanmaken']},

7:{"cmd":'mount | grep "[[:space:]]/tmp[[:space:]]" | grep noexec', "msg":"Zet de noexec optie voor de /tmp partitie", "results":results,"check":1,"ret":False,"comment":['De noexec mount optie bepaald dat de /tmp directorie geen uitvoerbare bestanden kan bevatten.','Omdat /tmp alleen bedoeld is voor tijdelijke opslag het is niet bedoeld en gevaarlijk als gebruikers hier code kunnen uitvoeren.']},

8:{"cmd":'grep "[[:space:]]/var[[:space:]]" /etc/fstab', "msg":"Maak een aparte partitie aan voor /var", "results":results,"check":1,"ret":False,
"comment":['De /var partitie wordt o.a. gebruikt door deamons en het opslaan van log bestanden',
'De /var directorie bevat world-writable bestanden en folders, er is een risico op het vol laten lopen van het systeem als de /var niet in een aparte partitie staat.']},

9:{"cmd":'grep -e "^/tmp[[:space:]]" /etc/fstab | grep /var/tmp', "msg":"Koppel de /var/tmp partitie op /tmp partitie", "results":results,"check":1,"ret":False,
"comment":['The /var/tmp directorie is normaliter een standalone directorie in de /var partitie. Het koppelen van /var/tmp op /tmp zorgt dat de /var/tmp niet kan worden verwijderd. ',
'Hiermee wordt voorkomen dat in de var/tmp directorie wel acties kunnen worden uitgevoerd die niet voor /tmp zijn toegestaan.']},


10:{"cmd":'grep "[[:space:]]/var/log/audit[[:space:]]" /etc/fstab', "msg":"Maak een aparte partitie aan voor /var/log/audit", "results":results,"check":1,"ret":False,
"comment":['De auditing daemon, auditd, slaat log data op in de  /var/log/audit directorie.',
'Hiermee worden twee onderdelen afgevangen, het voorkomen dat het systeem volloopt (grote bestanden) en het beveiligen van de log data.']},


11:{"cmd":'grep "[[:space:]]/home[[:space:]]" /etc/fstab', "msg":"Maak een aparte partitie aan voor /home", "results":results,"check":1,"ret":False,
"comment":['The /home directorie is de partitie voor gebruikers ',
'Hiermee wordt voorkomen dat het systeem kan volloopt en kan de /home gehardend worden.']},

12:{"cmd":'grep "[[:space:]]/home[[:space:]]" /etc/fstab', "msg":"Zet de nodev optie voor /home", "results":results,"check":1,"ret":False,
"comment":['Deze optie voorkomt dat character and block special devices aan de home directorie kunnen worden toegevoegd.', 'De home partitie is niet bedoeld voor het ondersteunen van devices.']},

13:{"cmd":'grep /dev/shm /etc/fstab | grep nodev', "msg":"Zet de nodev optie voor de /dev/shm partitie", "results":results,"check":1,"ret":False,
"comment":['The nodev optie bepaald dat de shared memory geen block of character special devices kan bevatten.', 'De shared memory partitie is niet bedoeld voor het ondersteunen van devices.']},

14:{"cmd":'grep /dev/shm /etc/fstab | grep nosuid', "msg":"Zet de nosuid optie voor de /dev/shm partitie", "results":results,"check":1,"ret":False,
"comment":['De nosuid optie bepaald dat setuid en setgid niet op uitvoerbare bestanden gezet kan worden',
'Hiermee wordt voorkomen dat gebruikers hun rechten kunnen laten escaleren.']},

15:{"cmd":'grep /dev/shm /etc/fstab | grep nodev', "msg":"Zet de noexec optie voor de /dev/shm partitie", "results":results,"check":1,"ret":False,
"comment":['De noexec optie voorkomt dat bestanden kunnen worden uitgevoerd in deze partitie.',
'Hiermee wordt voorkomen dat gebruikers bestanden vanuit het shared memory kunnen uitvoeren om de rechten te escaleren.']},

16:{"cmd":"df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d  \ ( -perm -0002 -a ! -perm -1000 \) 2>/dev/null", "msg":"Zet de Sticky Bit op alle World-Writable directories", "results":results,"check":1,"ret":False,
"comment":['Hiermee wordt voorkomen dat gebruikers niet de bestanden kunnen wijzigen waarvan zij geen eigenaar zijn.',
'Hiermee wordt voorkomen dat gebruikers hun rechten kunnen escaleren.']},


        }


permissies = {1:{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root", "msg":"World Writeable Directories voor gebruiker/groep 'Root'", "results":results,"check":False,"ret":False,"comment":False},
       2:{"cmd":"find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root", "msg":"World Writeable Directories voor gebruiker anders dan 'Root'", "results":results,"check":False,"ret":False,"comment":False},
       3:{"cmd":"find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null", "msg":"World Writable Bestanden", "results":results,"check":False,"ret":False,"comment":False},
       4:{"cmd":"find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null", "msg":"SUID/SGID Bestanden", "results":results,"check":False,"ret":False,"comment":False},
       5:{"cmd":"ls -ahlR /root 2>/dev/null", "msg":"Controle op toegangelijkheid root folder", "results":results,"check":False,"ret":False,"comment":False}
      }

tools = {1:{"cmd":"which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null", "msg":"Aangetroffen tools", "results":results,"check":False,"ret":False,"comment":['Een kwaadwillende kan met het aanroepen van deze bestanden zijn rechten escaleren','Deze bevinding dient handmatig verder te worden uitgewerkt']},

2:{"cmd":'rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey' , "msg":"Controle op de aanwezigheid van de Red Hat GPG Key", "results":results,"check":1,"ret":False,
3:['Red Hat cryptographically signs updates with a GPG key to verify that they are valid.',
'It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system.']},

4:{"cmd":'rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey' , "msg":"Verificatie dat gpgcheck globaal is geactiveerd", "results":results,"check":1,"ret":'gpg(Red Hat, Inc.',
"comment":['The gpgcheck option, found in the main section of the /etc/yum.conf file determines if an RPM package\'s signature is always checked prior to its installation.',
'It is important to ensure that an RPM\'s package signature is always checked prior to installation to ensure that the software is obtained from a trusted source.']},
5: {"cmd": "rpm -qVa | awk '$2 != \"c\" { print $0}'", "msg": "Test op pakket integriteit", "results":results,"check":False,"ret":False,"comment":False},
6: {"cmd": "rpm -qVa | awk '$2 != \"c\" { print $0}'", "msg": "Test op pakket integriteit", "results":results,"check":1,"ret":False,"comment":['Pakketten die niet volledig zijn of waarvan de rechten niet goed staan kunnen het systeem verzwakken','Ontbrekende pakketten zijn een veiligheids riscico. ']}

}


selinux = {
1: {"cmd":"cat /etc/selinux/config", "msg": "SELinux configuratie", "results":results,"check":False,"ret":False,"comment":False},
2: {"cmd":"usr/sbin/sestatus","msg": "SELinux sestatus opdracht", "results":results,"check":False,"ret":False,"comment":False},
3: {"cmd":"rpm -q setroubleshoot","msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":'is not installed',"comment":['','']},
4: {"cmd":"ps -eZ | egrep \"initrc\" | egrep -vw \"tr|ps|egrep|bash|awk\" | tr ':' ' ' | awk '{print $NF }'","msg": "Onbevestigde deamons",
"results":results,"check":1,"ret":False,"comment":['Deamons die niet zijn gedefineerd in de SELinux police erven de rechten van het parent proces', 
'Omdat de deamons worden gestart door het proces init, erven de processen de rechten over van initrc_t. Het gevolg hiervan is dat processen kunnen draaien met meer rechten dan noodzakelijk']},
5: {"cmd":"rpm -q mcstrans","msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":'is not installed',"comment":False},
6: {"cmd":'stat -L -c "%u %g" /boot/grub2/grub.cfg | egrep "0 0"',"msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":'0 0',"comment":['','']},
7: {"cmd":'stat -L -c "%a" /boot/grub2/grub.cfg | egrep ".00"',"msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":False,"comment":['','']},
"SECLIMITS": {"cmd":'grep "hard core" /etc/security/limits.conf',"msg": "Aanwezigheid van het pakket settroubleshoot", "results":results,"check":1,"ret":'* hard core 0',"comment":['','']},
#sysctl fs.suid_dumpable

}


ownhome = '''cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then owner=$(stat -L -c "%U" "$dir")
if [ "$owner" != "$user" ]; then
echo "The home directory ($dir) of user $user is owned by $owner." fi
fi done'''

dubgids ='''/bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\ while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
/etc/group | xargs`
echo "Duplicate GID ($2): ${grps}"
fi done'''

resuid = '''defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"
/bin/cat /etc/passwd |\
/bin/awk -F: '($3 < 500) { print $1" "$3 }' |\ while read user uid; do
found=0
for tUser in ${defUsers}
do
if [ ${user} = ${tUser} ]; then
found=1 fi
done
if [ $found -eq 0 ]; then
echo "User $user has a reserved UID ($uid)." fi
done'''

dubbelnamen = '''cat /etc/passwd | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
while read x ; do
[ -z "${x}" ] && break set - $x
if [ $1 -gt 1 ]; then
uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \ /etc/passwd | xargs`
echo "Duplicate User Name ($2): ${uids}" fi
done'''

forward = '''for dir in `/bin/cat /etc/passwd |\
/bin/awk -F: '{ print $6 }'`; do
if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then echo ".forward file $dir/.forward exists"
fi
done'''

netrsc = '''for dir in `/bin/cat /etc/passwd |\
/bin/awk -F: '{ print $6 }'`; do
if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
echo ".netrc file $dir/.netrc exists" fi
done'''

dupnamen = '''cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
  while read x ; do
  [ -z "${x}" ] && break set - $x
  if [ $1 -gt 1 ]; then
    gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
      /etc/group | xargs`
    echo "Duplicate Group Name ($2): ${gids}"
fi done'''

hashome = '''cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
echo "The home directory ($dir) of user $user does not exist."
fi
done'''

passwgroep = '''for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
grep -q -P "^.*?:x:$i:" /etc/group
if [ $? -ne 0 ]; then
echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" fi
done'''

rhost = '''for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do for file in $dir/.rhosts; do
if [ ! -h "$file" -a -f "$file" ]; then echo ".rhosts file in $dir"
fi done done'''

extra = {
11: {"cmd":rhost,"msg": "Own home","results":results,"check":1,"ret":False,"comment":[]},
12: {"cmd":passwgroep,"msg": "Own home","results":results,"check":1,"ret":False,"comment":[]},
12: {"cmd":hashome,"msg": "Own home","results":results,"check":1,"ret":False,"comment":[]},
13: {"cmd":ownhome,"msg": "Own home","results":results,"check":1,"ret":False,"comment":[]},
14: {"cmd":dubgids,"msg": "Aanwezigheid van dubbele gids","results":results,"check":1,"ret":False,"comment":[]},
15: {"cmd":dubbelnamen,"msg": "Aanwezigheid van dubbele groepen","results":results,"check":1,"ret":False,"comment":[]},
16: {"cmd":dupnamen,"msg": "Aanwezigheid van dubbele groepen","results":results,"check":1,"ret":False,"comment":[]},
17: {"cmd":netrsc,"msg": "Aanwezigheid van het Netrsc bestand",
"results":results,"check":1,"ret":False,"comment":[]},

18: {"cmd":forward,"msg": "aanwezigheid van het Forward bestand",
"results":results,"check":1,"ret":False,"comment":[]},
19: {"cmd":resuid,"msg": "aanwezigheid van het Forward bestand",
"results":results,"check":1,"ret":False,"comment":[]},
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
    print '\n[!] '+x['msg'] + '\nAudit:'+ x['cmd'] + '\n\nToelichting:\n'+ x['comment'][0] +'\n\nRisico:\n'+ x['comment'][1]



