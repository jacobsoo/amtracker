import re, os, zlib, base64
import urllib
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for Dendroid
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    909ac45cde3a9fb2f36d6b31cad07eec6f554b1a3d7cdc3d135589df53f83780
    e19823a1ba4a0e40cf459f4a0489fc257720cc0d71ecfb7ad94b3ca86fbd85d1
    7ab45b02d1a47a291f2dba3f6d4b3f359f3ba47661e1568ff9885f4a475100e8
    ca53cdcbc80e364fe4fc1ec3173aaf0a1e74ce79879c0e9a57d66bf1f6095f80
    bfea0288a3c463f0f1646cf23eed920b49b90c5ff316d42715c8c7bf8ba1e2e5
'''

class Dendroid(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyDendroid(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szServices = "".join(a.get_services())
        matchObj = re.search( r'com\.connect\.MyService', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj==None:
            _log("[-] This is not Dendroid")
            return False
        else:
            if matchObj.group(0)=="com.connect.MyService":
                bRes = self.extract_config(apkfile)
                if bRes == True:
                    return True
                

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from Dendroid.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        string = ""
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if 'Lcom/connect/MyService;'.lower() in cls.get_name().lower():
                c2Found = False
                portFound = False
                c2 = ""
                port = ""
                string = None
                for method in cls.get_methods():
                    if '<init>'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if "=" in string:
                                    szTemp = (base64.b64decode(string)).decode("utf-8")
                                else:
                                    try:
                                        szTemp = (base64.b64decode(string)).decode("utf-8")
                                    except:
                                        szTemp = string
                            if inst.get_name() == 'iput-object':
                                if "encodedURL" in inst.get_output():
                                    szURL = szTemp
                                if "backupURL" in inst.get_output():
                                    szBackupURL = szTemp
                                if "encodedPassword" in inst.get_output():
                                    szPassword = szTemp
                _log('[+] Extracting from %s' % apkfile)
                _log('[+] C&C: [ %s ]' % szURL)
                _log('[+] password : [ %s ]\n' % szPassword)
                return True