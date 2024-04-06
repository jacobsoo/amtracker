import re, os, zlib, base64
import urllib
from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for Vamp
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    909ac45cde3a9fb2f36d6b31cad07eec6f554b1a3d7cdc3d135589df53f83780
    e19823a1ba4a0e40cf459f4a0489fc257720cc0d71ecfb7ad94b3ca86fbd85d1
    7ab45b02d1a47a291f2dba3f6d4b3f359f3ba47661e1568ff9885f4a475100e8
    ca53cdcbc80e364fe4fc1ec3173aaf0a1e74ce79879c0e9a57d66bf1f6095f80
    bfea0288a3c463f0f1646cf23eed920b49b90c5ff316d42715c8c7bf8ba1e2e5
'''

class Vamp(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyVamp(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szPackageName = a.get_package()
        if szPackageName=="ru.ok.android":
            bRes = self.extract_config2(apkfile)
            if bRes == True:
                return True
            else:
                _log("[-] This is not Vamp")

    def AESdecrypt(self, szData, key):
        key = md5(key.encode('utf-8')).hexdigest()
        szData = base64.b64decode(szData)
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(szData)
        c2 = str(plaintext.decode("utf-8"))
        c2 = c2[:c2.find('\x08')]
        _log("[+] AES decrypted data --> C&C : %s" % c2)
        return True
    
    #-----------------------------------------------------------------
    # extract_config2 : This extracts the C&C information from Vamp.
    #-----------------------------------------------------------------
    def extract_config2(self, apkfile):
        self.apkfile = apkfile
        string = ""
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        encIP = ""
        encKey = ""
        for cls in d.get_classes():
            if 'Lru/ok/android/b/a;'.lower() in cls.get_name().lower():
                string = None
                for method in cls.get_methods():
                    if '/a;->a(Landroid/content/Context;)'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if "=" in string:
                                    encIP = string
                                    _log("[+] Found encrypted C2 : %s" %encIP)
            if 'Lru/ok/android/b/b;'.lower() in cls.get_name().lower():
                string = None
                for method in cls.get_methods():
                    if '<clinit>'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if "=" in string and "=UTF-8" not in string:
                                    encKey = string
                                    _log("[+] Found MD5 hashed & Base64 encoded key : %s" %encKey)
        if encIP and encKey:
            bRes = self.AESdecrypt(encIP, encKey)
            if bRes:
                return True

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from Vamp.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        string = ""
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if '/app/AppController;'.lower() in cls.get_name().lower():
                for cls in d.get_classes():
                    if '/app/a;'.lower() in cls.get_name().lower():
                        c2 = []
                        string = None
                        for method in cls.get_methods():
                            if '<clinit>'.lower() in str(method).lower():
                                for inst in method.get_instructions():
                                    if inst.get_name() == 'const-string':
                                        string = inst.get_output().split(',')[-1].strip(" '")
                                        if "http" in string:
                                            c2.append(string.replace("@", "/"))
                                        elif "&ht&" in string:
                                            c2.append(string.replace("&", ""))
                        if len(c2)>0:
                            _log('Extracting from %s' % apkfile)
                            for i in range(len(c2)):
                                _log('C&C: [ %s ]' % c2[i])
                            return True