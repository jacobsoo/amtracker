import re, os, zlib, base64
import urllib
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for BladeHawk
    by Jacob Soo (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    7604a74d433adab8d01f5e020d9f2ef694f01e480f1e8777bb0950b4eb2a78b0
    bc0c55efffe32ba0d2bdc23d5aa9d60200b50c5a373bce9822af6316cdd4f2fb
    2a4cf22220b95ad1f802efd1ae8abea56e83dc598d66eb073d75882d20858e39
    60e1afb6092d686865e2e21088696be9b969b04acab079faa8d8f1671ba1635f
    d3033e7305b2c547c0682e75fcd06666688ed98f57f8ab45936ef127d654eb49
    e69699299e9718936826bb4b9a99b80a0094480911861f7d0cf1303caf7d19b2
'''

class BladeHawk(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyBladeHawk(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szServices = "".join(a.get_services())
        matchObj = re.search( r'dat\.a8andoserverx\.MainService', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj==None:
            _log("[-] This is not BladeHawk")
            return False
        else:
            bRes = self.extract_config(apkfile)
            return bRes
                

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from BladeHawk.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        string = ""
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        _log("[+] Potentially BladeHawk")
        for cls in d.get_classes():
            if '/dat/a8andoserverx/MainService$1'.lower() in cls.get_name().lower():
                c2Found = False
                portFound = False
                c2 = ""
                port = ""
                string = None
                szTemp = ""
                for method in cls.get_methods():
                    if ';->run()v'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                szTemp = string
                            if inst.get_name() == 'invoke-static':
                                if "net/InetAddress;->getByName" in inst.get_output():
                                    c2 = szTemp
                                    c2Found = True
                                elif "Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I" in inst.get_output():
                                    port = szTemp
                                    portFound = True
                            if c2Found and portFound:
                                break
        if self.isNotEmpty(c2):
            _log('[+] Extracting from %s' % self.apkfile)
            _log('[+] C&C: [ %s ]' % c2)
            _log('[+] Port : [ %s ]\n' % port)
            return True