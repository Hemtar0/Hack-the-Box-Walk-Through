# GetSimple Writeup w/o Metasploit

Hi everyone, This is my first writeup for hack the box platform after completing the "Getting started Module" or "GetSimpe CMS" Machine .

So lets dive in the penetration test process:

## Reconaisance:

First thing first, since we will use the IP of the target machine in several situations within the terminal, we will assign the IP address to a variable and use it through the remaining tasks:
`export ip=10.129.181.169`

Next lets scan our target machine to figure out open ports and running services, will start by running nmap tool as follow:
`nmap -sC -sV --open -oA ./scan/inital-$ip $ip`

- **-sC**: run default nmap scripts.
- **-sV**: start service detection and fingerprinting.
- **--open**: return open ports only.
- **-oA**: save nmap output result (All format: grepable, text and xml) in the specified path.

```bash
──(kali㉿kali)-[~/VMs/htb]
└─$ nmap -sC -sV --open -oA ./scan/inital-$ip $ip                                                                                                                     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-10 11:52 EDT
Nmap scan report for gettingstarted.htb (10.129.181.169)
Host is up (0.093s latency).
Not shown: 835 closed tcp ports (conn-refused), 163 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4c73a025f5fe817b822b3649a54dc85e (RSA)
|   256 e1c056d052042f3cac9ae7b1792bbb13 (ECDSA)
|_  256 523147140dc38e1573e3c424a23a1277 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/admin/
|_http-title: Welcome to GetSimple! - gettingstarted
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.97 seconds
 scanned in 13.97 seconds
```

From nmap output we found that two ports were being opened as follow:

- **Port 80**: which runs **Apache/2.4.41**
- **Port 22**: which runs **OpenSSH 8.2p1 Ubuntu** ,This version matches OpenSSH 1.8.2p1.

Before start investigating port 80, lets run more comprehensive nmap scan in the background to make sure we cover all bases.
Lets run nmap scan on all ports as follow:

`nmap -sV -sC -p- -oA ./scan/full-$ip $ip`

After running this scan, we have got the same result as previous one, This confirm that we didn't miss any ports.

* * *

## Enumeration:

Since we have port 80 opened on the target machine and running apache web server,lets start by identifying the technologies used by this website such as "programing language,content management system(CMS),blogging platforms,Java script libraries, web servers and others".

To identify these technologies, will run the following command:

```bash
┌──(kali㉿kali)-[~/VMs/htb] └─$ whatweb $ip
http://10.129.181.169 [200 OK] AddThis, Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.181.169], Script[text/javascript], Title[Welcome to GetSimple! - gettingstarted]
```