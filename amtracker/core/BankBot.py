import re, os, zlib, base64
import urllib
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for BankBot
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    909ac45cde3a9fb2f36d6b31cad07eec6f554b1a3d7cdc3d135589df53f83780
    e19823a1ba4a0e40cf459f4a0489fc257720cc0d71ecfb7ad94b3ca86fbd85d1
    7ab45b02d1a47a291f2dba3f6d4b3f359f3ba47661e1568ff9885f4a475100e8
    ca53cdcbc80e364fe4fc1ec3173aaf0a1e74ce79879c0e9a57d66bf1f6095f80
    bfea0288a3c463f0f1646cf23eed920b49b90c5ff316d42715c8c7bf8ba1e2e5
'''

class BankBot(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyBankBot(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szPackageName = a.get_package()
        if szPackageName=="com.example.livemusay.myapplication":
            _log("[+] This is BankBot")
            bRes = self.extract_config(apkfile)
            if bRes == True:
                return True
            else:
                _log("[-] This is not BankBot")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from BankBot.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        string = ""
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if '/PreSS;'.lower() in cls.get_name().lower():
                c2 = ""
                string = None
                for method in cls.get_methods():
                    if 'PreSS;->onCreate(Landroid/os/Bundle;)V'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if ":" in string:
                                    c2 = string
                if self.isNotEmpty(c2):
                    _log('[+] Extracting from %s' % self.apkfile)
                    _log('[+] C&C: [ %s ]' % c2)
                    return True
            elif '/GPS;'.lower() in cls.get_name().lower():
                c2 = ""
                string = None
                for method in cls.get_methods():
                    if 'b(Landroid/location/Location;)V'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if ":" in string:
                                    c2 = string
                if self.isNotEmpty(c2):
                    _log('[+] Extracting from %s' % self.apkfile)
                    _log('[+] C&C: [ %s ]' % c2)
                    return True