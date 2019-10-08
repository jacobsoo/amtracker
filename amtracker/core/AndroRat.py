import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for AndroRat
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    18f02dd87210fc75a7da90a7637bb0920453aee59bbc4bfd820b6576c3fd9dbe
    28f8b2b568529c2106fdc60e124ac5a412c8fa8bbe99f8c05d9b52e7b3954369
    5a0bbf3c206514177d22a4c0a4f88efc7e9c649d39df96f06283cace25116488
    65cf2b5bf57c79629d9ebc1a691de9b3db285729b73e34348391e51fd3947b4d
    85a3703cf9af26e842c264e7d247742e9658901af11e9f644b5b0b71effeef6e
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