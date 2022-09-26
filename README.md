# amtracker
Android Malware Tracker

This was originally part of a module for the framework that i'm constantly developing. The decoders were mostly making use of [Androguard](https://github.com/androguard) to extract the C2 or malware authors' credentials

One of the decoder is making use of [LIEF](https://github.com/lief-project/LIEF) to extract the C2 from the android malware samples.

There are several more config extractors which i haven't added yet.  If there are is a specific Android family which you want me to add it, please kindly let me know. The codes will require updates after i publish this repository.  

As the malware authors will probably edit their codes to prevent this tool from extracting useful information.

Currently, i've added config extractors for the following:
- AndroRat
- AhMyth
- APT-C-23
- APT-C-27
- BankBot
- ChinaSMSStealer
- Dendroid
- FakeSpy
- FlexBotnet
- Moqhao
- MuddyWater
- Saefko
- SandroRat
- Spynote
- Syrian Mobile Trojan
- TeleRat
- Triout
- Vamp
- WhiteBroad

### Usage
```python
 python amtracker.py [-f|-d] <filename>
```
