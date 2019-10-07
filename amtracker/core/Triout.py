import re, os, zlib, base64
import urllib
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for Triout
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    References : https://labs.bitdefender.com/2018/08/triout-spyware-framework-for-android-with-extensive-surveillance-capabilities/
    
    Hashes for samples:
    0585702e00fc8430672b12188abd5ddfbeb2a98f2272cee2c3c0274b2f99fd90
    e0c1d15b86a6bf908217a7a19c458ce5bae90321a6f571e229bcba1d53eda15c
    4f05b094306676d9e729adad3ee865a8a5fa67fcd3e88092eb42f954979e18ab
    f198deeca3fb5c0991cf6dd66843a28972ba9af065ad20eadab4b4c9a96c4a37
    b72a67a1c6f8b933405d47163121ed931c19f4177d27bbffe0eee44868c6e76d
    43046a925c4733117f09d9ef88440556c6f552ebf1321ef998552910aa63f1ec
'''

class Triout(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    def caesar(self, plainText, shift):
        cipherText = ""
        for ch in plainText:
          if ord(ch) >= 32 and ord(ch) <= 127:
            i3 = ((ord(ch) - 32) + shift) % 96
            if i3 < 0:
              i3 += 96
            cipherText += (chr) (i3 + 32)
        return cipherText

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyTriout(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szPackageName = a.get_package()
        if "com.xapps.SexGameForAdults" in szPackageName:
            bRes = self.extract_config(apkfile)
            if bRes == True:
                return True
            else:
                _log("[-] This is not Triout")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from Triout.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        string = ""
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if 'psp/jsp/datamd/v;'.lower() in cls.get_name().lower():
                c2 = ""
                string = None
                for method in cls.get_methods():
                    if '/v;-><clinit>()V'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if "." in string:
                                    c2 = string
                                elif "/" in string:
                                    c2 = self.caesar(string, -1)
                if self.isNotEmpty(c2):
                    _log('[+] Extracting from %s' % self.apkfile)
                    _log('[+] C&C: [ %s ]' % c2)
                    return True