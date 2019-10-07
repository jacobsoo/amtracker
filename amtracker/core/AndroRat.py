import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for AndroRat
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    a4802bceaa9bfe337460d5935626b85d5f497a0f5d13afe0539925f4e0748c5f
    fc3a6bc2dec16aa4f6b3ddcd88718ec2b6b03d5ea8e784ed03bc3bb70d323a40
    dff641baafbc26af4a7afc804d393aa67809e1b6e0f6b8c5dfb7108b34dc043f
    3585853bc1d6448810fae2fdd511b180294cb6f82d4caebbc099ac2e3a544c9b
    c6f926b31d991ec9b26f83908d3fcf64c5f764ec1df12a6cf34af8c09dbf03f6
'''

class AndroRat(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyAndroRat(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szPackageName = a.get_package()
        if "my.app.client" in szPackageName:
            bRes = self.extract_config(apkfile)
            if bRes == True:
                return True
            else:
                _log("[-] This is not AndroRat")
                return False
        else:
            _log("[-] This is not AndroRat")
            return False

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from AndroRat.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        string = ""
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if 'Lmy/app/client/ProcessCommand;'.lower() in cls.get_name().lower():
                c2Found = False
                portFound = False
                c2 = ""
                port = ""
                string = None
                for method in cls.get_methods():
                    if 'loadPreferences'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if c2Found == True:
                                    c2 = string
                                    c2Found = False
                                if string == 'ip':
                                    c2Found = True
                                if string == 'port':
                                    portFound = True
                            if inst.get_name() == 'const/16':
                                if portFound == True:
                                    string = inst.get_output().split(',')[-1].strip(" '")
                                    port = string
                            if c2 and port:
                                break
                server = ""
                if port:
                    server = "{0}:{1}".format(c2, str(port))
                else:
                    server = c2
                _log('[+] Extracting from %s' % apkfile)
                _log('[+] C&C: [ %s ]\n' % server)
                return True