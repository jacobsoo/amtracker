# amtracker
Android Malware Tracker

This was originally part of a module for the framework that i'm constantly developing. The decoders were mostly making use of [Androguard](https://github.com/androguard) to extract the C2 or malware authors' credentials

One of the decoder is making use of [LIEF](https://github.com/lief-project/LIEF) to extract the C2 from the android malware samples.

There are several more config extractors which i haven't added yet.  If there are is a specific Android family which you want me to add it, please kindly let me know. The codes will require updates after i publish this repository.  

As the malware authors will probably edit their codes to prevent this tool from extracting useful information.

Currently, i've added config extractors for the following:
- [AndroRat](https://www.bitdefender.com/blog/hotforsecurity/possibly-italy-born-android-rat-reported-in-china-find-bitdefender-researchers)
```shell
$ python.exe .\amtracker\amtracker.py -f 26ffbf3d4820572e10c8f0d7c4549f622152e16f1818a1a0417724b1fb8b94d2


 ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __
/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \
\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \
 \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\"\_\
  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/


 Extract intel from this Android mallie!
 Jacob Soo
 Copyright (c) 2018-2022

[+] Verifying if it's AndroRat.
[+] Extracting from 26ffbf3d4820572e10c8f0d7c4549f622152e16f1818a1a0417724b1fb8b94d2
[+] C&C: [ mehyaz.ddns.net:81 ]
```

- [AhMyth](https://www.welivesecurity.com/2019/08/22/first-spyware-android-ahmyth-google-play/)
```shell
$ python.exe .\amtracker\amtracker.py -f d4e16801c46f51f704ed439fe7648e9d93a2b8f571d7120657f64190f6028b23


 ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __
/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \
\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \
 \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\"\_\
  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/


 Extract intel from this Android mallie!
 Jacob Soo
 Copyright (c) 2018-2022

[+] Verifying if it's AhMyth.
[+] Extracting from d4e16801c46f51f704ed439fe7648e9d93a2b8f571d7120657f64190f6028b23
[+] C&C: [ http://217.11.29.164:44303 ]
```

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
