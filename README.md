# amtracker
Android Malware Tracker

This was originally part of a module for the framework that i'm constantly developing. The decoders were mostly making use of [Androguard](https://github.com/androguard) to extract the C2 or malware authors' credentials

One of the decoder is making use of [LIEF](https://github.com/lief-project/LIEF) to extract the C2 from the android malware samples.

There are several more config extractors which i haven't added yet.  If there are is a specific Android family which you want me to add it, please kindly let me know. The codes will require updates after i publish this repository.  

As the malware authors will probably edit their codes to prevent this tool from extracting useful information.

Currently, i've added config extractors for the following:
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

- [APT41](https://www.lookout.com/threat-intelligence/article/wyrmspy-dragonegg-surveillanceware-apt41)

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

- [BladeHawk](https://www.welivesecurity.com/2021/09/07/bladehawk-android-espionage-kurdish/)
```shell
$ python.exe .\amtracker\amtracker.py -f 2a4cf22220b95ad1f802efd1ae8abea56e83dc598d66eb073d75882d20858e39


 ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __
/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \
\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \
 \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\"\_\
  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/


 Extract intel from this Android mallie!
 Jacob Soo
 Copyright (c) 2018-2022

[+] Verifying if it's BladeHawk.
[+] Potentially BladeHawk
[+] Extracting from 2a4cf22220b95ad1f802efd1ae8abea56e83dc598d66eb073d75882d20858e39
[+] C&C: [ alex00.ddns.net ]
[+] Port : [ 4000 ]
```

- [CapraRAT](https://www.trendmicro.com/en_us/research/22/a/investigating-apt36-or-earth-karkaddans-attack-chain-and-malware.html)
```shell
$ python.exe .\amtracker\amtracker.py -f "C:\Users\admin\Desktop\Android malware\CapraRAT\d62705186c488bb26fccdb1404931223a887004fd6704ac1483e599a15e92792"


 ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __
/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \
\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \
 \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\"\_\
  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/


 Extract intel from this Android mallie!
 Jacob Soo
 Copyright (c) 2018-2022

[+] Verifying if it's CapraRAT.
[+] It's CapraRAT
[+] Extracting from C:\Users\admin\Desktop\Android malware\CapraRAT\d62705186c488bb26fccdb1404931223a887004fd6704ac1483e599a15e92792
[+] C2 : [ 80.241.209.53 ]
[+] C2 : [ shareboxs.net ]
[+] Ports : [ 12182 ]
```

- ChinaSMSStealer
- Dendroid
- FakeSpy
- FlexBotnet
- [MMRat](https://www.trendmicro.com/en_us/research/23/h/mmrat-carries-out-bank-fraud-via-fake-app-stores.html)
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
