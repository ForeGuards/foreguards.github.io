---
title: Blue Team Commands
categories: [commands]
tags: [blueteam,commands,network,memory,activedirectory,accouts,passwords,user,microsoft,linux,events,logs,malware,firewall,triage,hash,powershell,cmd,shell]              # TAG names should always be lowercase
---

# Windows Commands

Here are we going to find all blue team commands for Windows...

## Network Discovery

### Basic Network Discovery:

```shell
net view /all
net view \\<HOST NAME>
```

### Basic ping scan and write output to file:

```shell
for /L %I in (1,1,254) do ping -w 30 -n 1 192.168.1.%I | find "Reply" >> <OUTPUT FILE NAME>.txt
```

## DHCP

### Enable DHCP Server Logging:

```shell
reg add HKLM\System\CurrentControlSet\Services\DhcpServer\Parameters /v ActivityLogFlag /t REG_DWORD /d 1
```

#### Default DHCP Location Windows 2003/2008/2012:
 
```shell
%windir%\System32\Dhcp
```

## Hashing

### File checksum Integrity Verifier (FCIV):
Ref. http://support2.microsoft.com/kb/841290

```shell
fciv.exe <FILE TO HASH>
```

## USER ACTIVITY
Ref. https://technet.microsoft.com/en­-us/sysinternals/psloggedon.aspx

### Get users logged on:

```shell
psloggedon \\computername
```

### Script loop scan:

```shell
for /L %i in (1,1,254) do psloggedon \\192.168.l.%i >> C:\users_output.txt
```

## MICROSOFT BASELINE SECURITY ANALYZER (MBSA)

### Basic scan of a target IP address:

```shell
mbsacli.exe /target <TARGET IP ADDRESS> /n os+iis+sql+password
``` 

## PASSWORDS

### Change password:

```shell
net user <USER NAME> * /domain
net user <USER NAME> <NEW PASSWORD>
```

### Change password remotely:
Ref. https://technet.microsoft.com/en­-us/sysinternals/bb897543

```shell
pspasswd.exe \\<IP ADDRESS or NAME OF REMOTE COMPUTER> -u <REMOTE USER NAME> -p <NEW PASSWORD>
```

### Change password remotely:

```powerhshell
pspasswd.exe \\<IP ADDRESS or NAME OF REMOTE COMPUTER>
```

## HOST FILE

### Add new malicious domain to hosts file, and route to localhost:

```shell
echo 127.0.0.1 <MALICIOUS DOMAIN> >> C:\Windows\System32\drivers\etc\hosts
```

Check if hosts file is working, by sending ping to 127.0.0.1:

```shell
ping <MALICIOUS DOMAIN> -n 1
```

## LOG AUDITING

### Get a specific list of events based on Event ID:
```powershell
Get-Eventlog Security I ? { $_.Eventid -eq 4800}
Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4774}
```

### Account Logon - Audit Credential Validation Last 14 Days:
```powershell
Get-Eventlog Security 4768,4771,4772,4769,4770,4649,4778,4779,4800,4801,48 02,4803,5378,5632,5633 -after ((get-date).addDays(- 14))
```

### Account - Logon/Logoff:
```powershell
Get-Eventlog Security 4625,4634,4647,4624,4625,4648,4675,6272,6273,6274,62 75,6276,6277,6278,6279,6280,4649,4778,4779,4800,4801
,4802,4803,5378,5632,5633,4964 -after ((get­ date).addDays(-1))
```

## LIVE TRIAGE

### SYSTEM INFORMATION
```shell
echo %DATE% %TIME%
hostname
systeminfo
systeminfo I findstr /B /C:"OS Name" /C:"OS Version"
wmic csproduct get name
wmic bios get serialnumber
wmic computersystem list brief
```

Ref. https://technet.microsoft.com/en­-us/sysinternals/psinfo.aspx
```shell
psinfo -accepteula -s -h -d
```

## USER INFORMATION
```shell
whoami
net users
net localgroup administrators
net group administrators
wmic rdtoggle list
wmic useraccount list
wmic group list
wmic netlogin get name,lastlogon,badpasswordcount
wmic netclient list brief C:\> doskey /history> history.txt
```

## NETWORK INFORMATION
```shell
netstat -e
netstat -naob
netstat -nr
netstat -vb
nbtstat -s
route print
arp -a
ipconfig /displaydns
netsh winhttp show proxy
ipconfig /allcompartments /all
netsh wlan show interfaces
netsh wlan show all
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings"
type %SYSTEMROOT%\system32\drivers\etc\hosts
wmic nicconfig get descriptions,IPaddress,MACaddress
wmic netuse get name,username,connectiontype,localname
```

## SERVICE INFORMATION
```shell
at
tasklist
tasklist /SVC
tasklist /SVC /fi "imagename eq svchost.exe"
schtasks
net start
sc query 
wmic service list brief | findstr "Running"
wmic service list config 
wmic process list brief 
wmic process list status 
wmic process list memory 
wmic job list brief
```

```powershell
Get-Service I Where-Object { $_.Status -eq "running" }
```

### List of all processes and then all loaded modules:
```powershell
Get-Process !select modules!Foreach­ Object{$_.modules}
``` 

## POLICY, PATCH AND SETTINGS INFORMATION

```shell
gpresult /H report.html /F
```

### List GPO software installed:
```shell
reg query "HKLM\Software\Microsoft\Windows\Current Version\Group Policy\AppMgmt"
``` 

## AUTORUN AND AUTOLOAD INFORMATION

### Startup information:
```shell
wmic startup list full
wmic ntdomain list brief
```

### Show all autorun files, export to csv and check with VirusTotal:

```shell
autorunsc.exe -accepteula -a -c -i -e -f -l -m -v
```

## LOGS

### Copy event logs:
```shell
wevtutil epl Security C:\<BACK UP PATH>\mylogs.evtx
wevtutil epl System C:\<BACK UP PATH>\mylogs.evtx
wevtutil epl Application C:\<BACK UP PATH>\mylogs.evtx
```

## FILES, DRIVES AND SHARES INFORMATION

### Find multiple file types or a file:
```shell
dir /A /5 /T:A *,exe *,dll *,bat *·PS1 *,zip
dir /A /5 /T:A <BAD FILE NAME>,exe
```

### Find executable (.exe) files newer than Jan 1, 2017:
```shell
forfiles /p C:\ /M *,exe /5 /0 +1/1/2017 /C "shell /c echo @fdate @ftime @path"
```

### Find multiple files types using loop:
```shell
for %G in (.exe, .dll, .bat, .ps) do forfiles - p "C:" -m *%G -s -d +1/1/2017 -c "shell /c echo @fdate @ftime @path"
```

### Search for files newer than date:
```shell
forfiles /PC:\ /5 /0 +1/01/2017 /C "shell /c echo @path @fdate"
``` 

### Find large files: (example <20 MB)
```shell
forfiles /5 /M * /C "shell /c if @fsize GEO 2097152 echo @path @fsize"
```

### Find files with Alternate Data Streams:
Ref. https://technet.microsoft.com/en­-us/sysinternals/streams.aspx
```shell 
streams -s <FILE OR DIRECTORY>
```

#### Find files with bad signature into csv:
Ref. https://technet.microsoft.com/en­-us/sysinternals/bb897441.aspx
```shell
sigcheck -c -h -s -u -nobanner <FILE OR DIRECTORY> > <OUTPUT FILENAME>,csv
```

### Find and show only unsigned files with bad signature in C:
```shell
sigcheck -e -u -vr -s C:\
```

### Lit loaded unsigned Dlls:
Ref. https://technet.microsoft.com/en­-us/sysinternals/bb896656.aspx
```shell
listdlls.exe -u
listdlls.exe -u <PROCESS NAME OR PID>
```

## MALWARE ANALYSIS

### Mount live Sysinternats toots drive:
```html
\\live.sysinternals.com\tools
```

#### Signature check of dlt, exe files:
Ref. http://technet.microsoft.com/en­-us/sysinternals/bb897441.aspx
```shell
sigcheck.exe -u -e (:\<DIRECTORY>
```

### Send to VirusTotat:
```shell
sigcheck.exe -vt <SUSPICIOUS FILE NAME>
```

### Find Malware with PID in memory dump using Volatility:
```python
python vol.py -f <MEMORY DUMP FILE NAME>.raw - profile=Win7SPFix64 malfind -p <PID #> -D /<OUTPUT DUMP DIRECTORY>
```

### Find suspicious processes using Volatility:
```python
python vol.py -f <MEMORY DUMP FILE NAME>.raw - profile=Win7SPFix64 pslist
python vol.py -f <MEMORY DUMP FILE NAME>,raw - profile=Win7SPFix64 pstree
```

### Find suspicious dlls using Volatility:
```python
python vol.py -f <MEMORY DUMP FILE NAME>.raw - profile=Win7SPFix64 dlllist
python vol.py -f <MEMORY DUMP FILE NAME>.raw - profile=Win7SPFix64 dlldump -D /<OUTPUT DUMP DIRECTORY>
```

### Malware analysis parsing Tool:
Ref. https://github.com/Defense-Cyber-Crime­-Center/DC3-MWCP

### Install dc3-mwcp tool:
```python
setup.py install
```

### Use dc3-mwcp tool to parse suspicious file:
```python
mwcp-tool.py -p <SUSPICIOUS FILE NAME>
```

## HARD DRIVE AND MEMORY ACQUISITION

Create memory dump remotely:<br>
Ref. http://kromer.pl/malware-analysis/memory­ forensics-using-volatility-toolkit-to-extract­ malware-samples-from-memory-dump/ <br>
Ref. http://sourceforge.net/projects/mdd/ <br>
Ref. https://technet.microsoft.com/en­ us/sysinternals/psexec.aspx

```shell
psexec.exe \\<HOST NAME OR IP ADDRESS> -u <DOMAIN>\<PRIVILEGED ACCOUNT> -p <PASSWORD> -c mdd_l,3.exe --o C:\memory.dmp
```

### Extract exe/dll from memory dump: <br>
Ref. https://github.com/volatilityfoundation/volatility

```shell
volatility dlldump -f memory.dmp -0 dumps/ C:\> volatility procmemdump -f memory.dmp -0 dumps/ Create hard drive image using dc3dd of C:\:
```

Ref. "https://sourceforge.net/projects/dc3dd/files/dc3dd/7.2%20-%20Windows/"
```shell
dc3dd.exe if=\\,\c: of=d:\<ATTACHED OR TARGET DRIVE>\<IMAGE NAME>,dd hash=md5 log=d:\<MOUNTED LOCATION>\<LOG NAME>,log
```

## BACKUP

### Backup All GPOs in domain and save to Path:
```powershell
Backup-Gpo -All -Path \\<SERVER>\<PATH TO BACKUPS>
```

### Restore All GPOs in domain and save to Path:
```powershell
Restore-GPO -All -Domain <INSERT DOMAIN NAME> -Path \\Serverl\GpoBackups
```

### List all shadow files:
```shell
vssadmin List Shadows
```

### Browse Shadow Copy for files/folders:
```shell
mklink /d c:\<CREATE FOLDER>\<PROVIDE FOLDER NAME BUT DO NOT CREATE> \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyl\
``` 

## OS CHEATS

### Pipe output to clipboard:
```shell
some_command.exe I clip
```

### Output clip to file: (Requires PowerShell 5)
```powershell
Get-Clipboard> clip.txt
```

---

# Linux Commands
Here are you going to find all blue team commands for Linux


## NETWORK DISCOVERY

### Net view scan:
```shell
smbtree -b
smbtree -D
smbtree -5
```

### View open 5MB shares:

```shell
smbclient -L <HOST NAME> # smbstatus
```

### Basic ping scan:

```shell
for ip in $(seq1254); doping-c1 192.168.1.$ip>/dev/null; [ $? -eq 0 ] && echo
"192.168.1.$ip UP" 11 : ; done
```

## DNS

### Start DNS logging:

```shell
rndc querylog
```

### View DNS logs:

```shell
tail -f /var/log/messages I grep named
```

## HOST SYSTEM FIREWALLS

### Export existing iptables firewall rules:

```shell
iptables-save > firewall.out
```

### Edit firewall rules and chains in firewall.out and save the file:

```shell
vi firewall.out
```

### Apply iptables:

```shell
iptables-restore < firewall.out
```

## TCPDUMP

### View traffic with timestamps and don't convert addresses and be verbose:
```shell
tcpdump -tttt -n -vv
```

### Find top talkers after 1000 packets (Potential
DDoS):
```shell
tcpdump -nn -c 1000 jawk '{print $3}' I cut -d. - fl-4 I sort-n I uniq-c I sort-nr
```

### View traffic only between two hosts:
```shell
tcpdump host 10.0.0.1 && host 10.0.0.2
```

### View all traffic except from a net or a host:
```shell
tcpdump not net 10.10 && not host 192.168.1,2
```

### View host and either of two other hosts:
```shell
tcpdump host 10,10,10.10 && \(10,10.10.20 or 10,10,10,30\)
```

### Save pcap file on rotating size:

```shell
tcpdump -n -s65535 -c 1000 -w '%host_%Y-%m­ %d_%H:%M:%S.pcap'
```

### Grab traffic that contains the word pass:
```shell
tcpdump -n -A -s0 I grep pass
```

### Grab many clear text protocol passwords:
```shell
tcpdump -n -A -s0 port http or port ftp or port smtp or port imap or port pop3 I egrep -i
'pass=lpwd=llog=llogin=luser=lusername=lpw=lpassw=IP asswd=lpassword=lpass:Iuser:lusername:Ipassword:Ilog in:Ipass Iuser ' --color=auto --line-buffered -B20
``` 

## LOG AUDITING

### Authentication logs in Ubuntu:
```shell
tail /var/log/auth.log
grep -i "fail" /var/log/auth.log
```

### User login logs in Ubuntu:
```shell
tail /var/
```

### Look at samba activity:
```shell
grep -i samba /var/log/syslog
```

### Look at cron activity:
```shell
grep -i cron /var/log/syslog
``` 

### Look at sudo activity:
```shell
grep -i sudo /var/log/auth. log
```

### Monitor for new created files every Smin:
```shell
watch -n 300 -d ls -lR /<WEB DIRECTORY>
```

### Look where traffic is coming from:
```shell 
cat <LOG FILE NAME> I fgrep -v <YOUR DOMAIN> I cut -d\" -f4 I grep -v ""-
```

### Monitor for TCP connections every 5 seconds:
```shell
netstat -ac 5 I grep tcp
```

## LIVE TRIAGE

## USER INFORMATION

### View logged in users:
```shell
w
```

### Show if a user has ever logged in remotely: 
```shell
lastlog
last
```

### View failed logins:
```shell
faillog - a
```

### View local user accounts:
```shell
cat/etc/passwd
cat/etc/shadow
```

### View local groups:
```shell
cat/etc/group
```

### View sudo access:
```shell
cat/etc/sudoers
```

### View accounts with UID 0:
```shell
awk -F: '($3 == "0") {p rint}' /etc/passwd # egrep ':0+' /etc/passwd
```

### List of files opened by user:
```shell
lsof -u <USER NAME>
```

### View network connections: # netstat -antup
```shell
netstat -plantux
```

### View listening ports:
```shell
netstat -nap
```

### List of open files, using the network:
```shell
lsof -nPi I cut -f 1 -d " "I uniq I tail -n +2 List of open files on specific process:
lsof -c <SERVICE NAME>
```

### Get all open files of a specific process ID:
```shell
lsof -p <PID>
```

### List of unlinked processes running:
```shell
lsof +Ll
```

### Get path of suspicious process PID:
```shell
ls -al /proc/<PID>/exe
``` 

### Save file for further malware binary analysis:
```shell
cp /proc/<PID>/exe >/<SUSPICIOUS FILE NAME TO SAVE>,elf
```

### Monitor logs in real-time:
```shell
less +F /var/log/messages
```

### List cron jobs:
```shell
crontab -l
```

### List cron jobs by root and other UID 0 accounts:
```shell
crontab -u root -l
``` 

### Review for unusual cron jobs:
```shell
cat /etc/crontab
ls /etc/cron.*
```

### Run Linux Malware Detect (LMD):

```shell
wget http://www.rfxn.com/downloads/maldetect­ current.tar.gz
tar xfz maldetect-current.tar.gz #cd maldetect-*
./install.sh
```

### Get LMD updates:
```shell
maldet -u
```

### Run LMD scan on directory: 
```shell
maldet -a /<DIRECTORY>
```

## HASH QUERY

### VirusTotal online API query:

Ref. https://www.virustotal.com/en/documentation/public­-api/ 
(Prerequisite: Need a VT API Key)

### Send a suspicious hash to VirtusTotal using cURL:
```shell
curl -v --request POST --url 'https://www.virustotal.com/vtapi/v2/file/report' -d
apikey=<VT API KEY> -d 'resource=<SUSPICIOUS FILE HASH>'
```

### Send a suspicious file to VirusTotal using cURL:
```shell
curl -v -F 'file=/<PATH TO FILE>/<SUSPICIOUS FILE NAME>' -F apikey=<VT API KEY> https://www.virustotal.com/vtapi/v2/file/scan
```

### Team Cymru API:
Ref. https://hash.cymru.com, http://totalhash.com 

Team Cymru malware hash lookup using whois: (Note:

### Output is timestamp of last seen and detection rate)
```shell
whois -h hash,cymru.com <SUSPICIOUS FILE HASH>
```

### Create memory dump:
```shell
dd if=/dev/fmem of=/tmp/<MEMORY FILE NAME>.dd
```

### Create memory dump using LiME:
Ref. https://github.com/504ensicslabs/lime
```shell
wget https://github.com/504ensicslabs/LiME/archive/master .zip
unzip master.zip
cd LiME-master/src
make
cp lime-*,ko /media/=/media/ExternalUSBDriveName/
insmod lime-3.13.0-79-generic.ko "path=/media/ExternalUSBDriveName/<MEMORY DUMP>,lime format=raw"
```

### Make copy of suspicious process using process ID:
```shell
cp /proc/<SUSPICIOUS PROCESS ID>/exe /<NEW SAVED LOCATION>
```

### Grab memory core dump of suspicious process:
```shell
gcore <PIO>
```

### Strings on gcore file:
```shell
strings gcore.*
```

### Create a hard drive/partition copy with tog and hash options:
```shell
dd if=<INPUT DEVICE> of=<IMAGE FILE NAME>
dc3dd if=/dev/<TARGET DRIVE EXAMPLE SDA OR SDAl> of=/dev/<MOUNTED LOCATION>\<FILE NAME>.img hash=md5 log=/<MOUNTED LOCATION>/<LOG NAME>.log
```

Create a remote hard drive/partition over SSH:
```shell
dd if=/dev/<INPUT DEVICE> I ssh <USER NAME>@<DESTINATION IP ADDRESS> "dd of=<DESTINATION PATH>"
```

### Send hard drive image zipped over netcat: 
#### Sending host:
```shell
bzip2 -c /dev/<INPUT DEVICE> I nc <DESTINATION IP ADDRESS> <PICK A PORT>
```
#### Receiving host:
```shell
nc -p <PICK SAME PORT> -l lbzip2 -d I dd of=/dev/sdb
```

### Send hard drive image over netcat:
#### Sending host:
```shell
dd if=/dev/<INPUT DEVICE> bs=16M I nc <PORT>
```
#### Receiving host with Pipe Viewer meter:
```shell
nc -p <SAME PORT> -l -vv I pv -r I dd of=/dev/<INPUT DEVICE> bs=16M
```

