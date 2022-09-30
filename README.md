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

- [APT-C-23](https://symantec-enterprise-blogs.security.com/blogs/expert-perspectives/ongoing-android-malware-campaign-targets-palestinians-part-2)
```shell
$ python.exe .\amtracker\amtracker.py -f ca87cc9898af3883eca81aca658109fdd7ca2529dfbd45a25e0c6e7cf0b526e5


 ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __
/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \
\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \
 \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\"\_\
  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/


 Extract intel from this Android mallie!
 Jacob Soo
 Copyright (c) 2018-2022

[+] Verifying if it's APT-C-23.
[+] It's APT-C-23
[+] Extracting from ca87cc9898af3883eca81aca658109fdd7ca2529dfbd45a25e0c6e7cf0b526e5
[+] Extracted C2: http://upload101.net/android/domains
[+] Extracted C2: http://upload999.info
```

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
- [Xenomorph](https://www.threatfabric.com/blogs/bugdrop-new-dropper-bypassing-google-security-measures.html)
```shell
$ python.exe .\amtracker\amtracker.py -f 65c655663b9bd756864591a605ab935e52e5295735cb8d31d16e1a6bc2c19c28.apk


 ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __
/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \
\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \
 \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\"\_\
  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/


 Extract intel from this Android mallie!
 Jacob Soo
 Copyright (c) 2018-2022

[+] Verifying if it's Xenomorph.
Requested API level 31 is larger than maximum we have, returning API level 28 instead.
Requested API level 31 is larger than maximum we have, returning API level 28 instead.
[+] It's Xenomorph
[+] Extracting from 65c655663b9bd756864591a605ab935e52e5295735cb8d31d16e1a6bc2c19c28.apk
[+] C&C : [ datasciensonline.us ]
[+] C&C : [ gogoanalytics.click ]
[+] C&C : [ gogoanalytics.digital ]
[+] C&C : [ sallaka.com ]
[+] C&C : [ mybizzl.com ]
```

### Usage
```python
 python amtracker.py [-f|-d] <filename>
```
