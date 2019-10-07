import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    Hashes for samples:
    ab99a33e7528b6b95c03e51336ad7fd54442722f08a3634b96dead3a091a6da1
    8007346a57fbe2965b6a58b4a2d7bb21e8230fb642707409bb91d5c1010a9f80
    8fad8429b4e0ed5c2ed6dffec4989fd6861cf7afa47695e7d53bb0cc3196e1f8
    d15648a84b46f97c93f59b0b5b09d8b0572f972292bfda31eb3864f412d86d51
    fad306dd9f1bdd6c132a074446947ac7a57e42df975cb440a26e051ee4cf6b99
'''

class AhMyth(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())
    
    def verifyAhMyth(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szPackageName = a.get_package()
        if "ahmyth.mine.king.ahmyth" in szPackageName:
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            _log("[-] This is not AhMyth")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from AhMyth.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        bTeleRat = False
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if 'ahmyth/mine/king/ahmyth/IOSocket;'.lower() in cls.get_name().lower():
                c2 = ""
                string = None
                for method in cls.get_methods():
                    if 'IOSocket;-><init>()V'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if "http://" in string:
                                    c2 = string[:-7]
                if self.isNotEmpty(c2):
                    _log('[+] Extracting from %s' % apkfile)
                    _log('[+] C&C: [ %s ]' % c2)
                    return True