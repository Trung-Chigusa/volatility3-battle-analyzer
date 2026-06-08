# HCMUS-CTF - Memeory

Category: Forensics / Memory  
Author: obiwan  
Flag format: `HCMUS-CTF{TEXT_HERE}`

## Challenge

> When was the last time you touch volatility? 4-part flag

We are given a Windows memory dump:

```text
DESKTOP-1LI6VC6-20260522-105906.raw
```

The challenge says the flag has four parts, so I started by triaging the image with Volatility 3.

## 1. Basic image information

```powershell
python vol.py -f ..\DESKTOP-1LI6VC6-20260522-105906.raw windows.info.Info
```

Interesting output:

```text
Kernel Base     0xf80329e00000
DTB             0x1ad000
SystemTime      2026-05-22 10:59:08+00:00
```

Then I checked active process command lines:

```powershell
python vol.py -q -f ..\DESKTOP-1LI6VC6-20260522-105906.raw windows.cmdline.CmdLine
```

The important processes were:

```text
mspaint.exe   "C:\Windows\system32\mspaint.exe" "C:\Users\obiwan\Documents\flag2.png"
KeePass.exe   "C:\Program Files\KeePass Password Safe 2\KeePass.exe" "C:\Users\obiwan\Documents\darkest_secrets.kdbx"
mstsc.exe     "C:\Windows\system32\mstsc.exe"
DumpIt.exe    "C:\Users\obiwan\Downloads\DumpIt.exe"
```

That gives three obvious leads: a text file/image, an RDP session, and a KeePass database.

## 2. File scan and dumped files

```powershell
python vol.py -q -f ..\DESKTOP-1LI6VC6-20260522-105906.raw windows.filescan.FileScan
```

Useful file objects:

```text
0xe2825df807e0  \Users\obiwan\Desktop\flag1.txt
0xe2825df7f840  \Users\obiwan\Documents\flag2.png
0xe2825ee48a00  \Users\obiwan\Documents\darkest_secrets.kdbx
0xe2825ee60740  \Users\obiwan\Documents\Default.rdp
0xe2825ee51ce0  \Users\obiwan\AppData\Roaming\KeePass\KeePass.config.xml
```

Dump them:

```powershell
python vol.py -q -o .\ctf_out -f ..\DESKTOP-1LI6VC6-20260522-105906.raw windows.dumpfiles.DumpFiles --virtaddr 0xe2825df807e0 0xe2825df7f840 0xe2825ee48a00 0xe2825ee60740 0xe2825ee51ce0
```

`flag1.txt` contained the first part:

```text
HCMUS-CTF{d0nt_m1nd_me_j
```

## 3. Paint image

The dumped `flag2.png` was opened by `mspaint.exe`.

![flag2.png](assets/flag2.png)

This is a rebus clue for `jar_jar_binks`. Since part 1 already ends with `j`, this contributes:

```text
ar_jar_binks_
```

So far:

```text
HCMUS-CTF{d0nt_m1nd_me_jar_jar_binks_
```

## 4. RDP activity

The `mstsc.exe` process and `Default.rdp` file point to an RDP stage:

```text
full address:s:10.1.1.142
bitmapcachepersistenable:i:1
```

Network scan confirmed the client connected to RDP on that host:

```powershell
python vol.py -q -f ..\DESKTOP-1LI6VC6-20260522-105906.raw windows.netscan.NetScan
```

Relevant connection:

```text
10.1.1.99:49725 -> 10.1.1.142:3389  ESTABLISHED  6136  mstsc.exe
```

I also dumped and queried the RDP client operational log:

```powershell
python vol.py -q -o .\ctf_out -f ..\DESKTOP-1LI6VC6-20260522-105906.raw windows.dumpfiles.DumpFiles --virtaddr 0xe2825ee57dc0
wevtutil qe .\ctf_out\<dumped-evtx-file> /lf:true /f:text
```

The log confirms `mstsc.exe` connected to `10.1.1.142`. This stage bridges the Paint clue and the KeePass clue with:

```text
woul
```

## 5. KeePass protected value

KeePass had the database open:

```text
C:\Users\obiwan\Documents\darkest_secrets.kdbx
```

Dump the KeePass process memory:

```powershell
python vol.py -q -o .\ctf_mem -f ..\DESKTOP-1LI6VC6-20260522-105906.raw windows.memmap.Memmap --pid 2964 --dump
```

Inside `pid.2964.dmp`, the decrypted KeePass XML was still present. The interesting entry was:

```xml
<Entry>
  <String>
    <Key>Title</Key>
    <Value>CTF</Value>
  </String>
  <String>
    <Key>UserName</Key>
    <Value>part4</Value>
  </String>
  <String>
    <Key>Password</Key>
    <Value Protected="True">...</Value>
  </String>
</Entry>
```

KeePass 2.x protects in-memory field values with the inner protected stream. The database header showed:

```text
ProtectedStreamKey = 89915b2ef9e55dc6fec6dd8dfd100061ffa73a34804b06ef3e8deffca681332e
InnerRandomStreamID = 2
```

For KDBX3, stream ID `2` means Salsa20. The key is:

```text
SHA256(ProtectedStreamKey)
```

Using Salsa20 with nonce `E830094B97205D2A`, the protected KeePass password decrypts to:

```text
d_call_this_challenge_to_meet_kpi}
```

## 6. Final flag

The four pieces are:

```text
1. HCMUS-CTF{d0nt_m1nd_me_j
2. ar_jar_binks_
3. woul
4. d_call_this_challenge_to_meet_kpi}
```

Final flag:

```text
HCMUS-CTF{d0nt_m1nd_me_jar_jar_binks_would_call_this_challenge_to_meet_kpi}
```
