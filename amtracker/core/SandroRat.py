import re, os, zlib, base64
from typing import List
import struct
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for SandroRat
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    7ac44c1854977a2eb586f74015771036b339ce04f347f830dac95f63e401c3dd
    07a8c2778c42d4d10eabba697dfcc6af35504f070ce81c053147604846df3521
    f02b212bdb11e6e334c0bb40b64a5d298a120a853d71405ef6ab5995031653f2
    4ce44b0addc9f69a806a4ae12d65b6457bbd0688ec6691eb964006c1ec390fe9
    a3a6eb4d93e01f038f5ee7ddbc0d7f0403c27b746e7d806410cdd81aa402dcaf
'''

class SandroRat(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifySandroRat(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'net\.droidjack\.server', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        bRes = self.extract_config(apkfile)
        if bRes == True:
            return True
        else:
            _log("[-] This is not SandroRat")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from SandroRat.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        try:
            self.apkfile = apkfile
            string = ""
            bIndicate = False
            a = apk.APK(self.apkfile)
            d = dvm.DalvikVMFormat(a.get_dex())
            for cls in d.get_classes():
                if 'Lnet/droidjack/server/MainActivity;'.lower() in cls.get_name().lower():
                    for method in cls.get_methods():
                        if 'onCreate'.lower() in str(method).lower():
                            for inst in method.get_instructions():
                                if inst.get_name() == 'sget-byte':
                                    string = inst.get_output().split(',')[-1].strip(" '")
                                    string, szMet = string.split("->")
                                    bIndicate = True
                                    break
            if bIndicate:
                for cls in d.get_classes():
                    if string.lower() in cls.get_name().lower():
                        c2 = ""
                        port = ""
                        szTemp = None
                        for method in cls.get_methods():
                            if '<clinit>'.lower() in str(method).lower():
                                for inst in method.get_instructions():
                                    if inst.get_name() == 'const-string':
                                        c2 = inst.get_output().split(',')[-1].strip(" '")
                                    if inst.get_name() == 'const/16':
                                        port = inst.get_output().split(',')[-1].strip(" '")
                                    if c2 and port:
                                        break
                        server = ""
                        if port:
                            server = "{0}:{1}".format(c2, str(port))
                        else:
                            server = c2
                        _log('[+] Extracting from %s' % self.apkfile)
                        _log('[+] C&C: [ %s ]\n' % server)
                        return True
        except struct.error:
            _log("[-] Possibly corrupted APK")