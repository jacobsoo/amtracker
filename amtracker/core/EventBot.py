import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    Hashes for samples:
    42344ae56337fe802340385c821b6be151483d99ae3572e50e76dfc8b790033a
    b57d2cef4419ca3dfac736825dc0e444e52d22bb517ca185d415f13af856d966
    fa6897c95fc9e48ca17275167420ddb5911497055cc3b84ef80d0421571a1902
    f2a5bb87811a3cef9e81d42a27065f2c8f546d5dfbd5a121cb5f5ae57242dcd3
    7b1ac3a8caa556c9208d4db62395cca2f8a53420e5d51a1537bc45622e41b63f
'''

class EventBot(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())
    
    def verifyEventBot(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szPackageName = a.get_package()
        if "example.eventbot" in szPackageName:
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            _log("[-] This is not EventBot")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from EventBot.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        bEventBot = False
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if '/example/eventbot/cfg'.lower() in cls.get_name().lower():
                _log("  [+] This is EventBot.")
                bEventBot = True
                c2 = []
                string = None
                for method in cls.get_methods():
                    if 'eventbot/cfg;-><clinit>()'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(';')#.strip(" '")
                                if "http" in string[0]:
                                    c2.append(string[0].strip("v0, '"))
                                    c2.append( string[1].strip(" '"))
                if self.isNotEmpty(c2[0]):
                    _log('  [+] Extracting from %s' % self.apkfile)
                    _log('  [+] C&C : [ %s ]' % c2[0])
                    _log('  [+] C&C : [ %s ]' % c2[1])
                    return True
        if bEventBot==False:
            _log("[-] This is not EventBot")