import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    Hashes for samples:
    ca87cc9898af3883eca81aca658109fdd7ca2529dfbd45a25e0c6e7cf0b526e5
    e14f99608a8d16cdd17786d218e173b44bbf9d5e30387d949a72604ec29cc4c6
    65495e63799a0e919937d83dee6f059a1cd2affe5411ba7d6fc454e36c0571e8
    9d629d20fdb0d4650a3c1a308028c7c51d673770a988d78cccb4bb819ffc08a8
    dfbd6e916ab1660f4fd87552fd392e43122e797ca8d66aa3123623cd70b78d0c
'''

class APT_C_23(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())
    
    def verifyAPT_C_23(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(apkfile)
        szPermissions = " ".join(a.get_permissions())
        matchObj = re.search( r'android\.permission\.INTERNET', szPermissions, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'MainActivity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szReceivers = "".join(a.get_receivers())
        matchObj = re.search( r'eceivers\.CallReceiver', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szServices = "".join(a.get_services())
        matchObj = re.search( r'services\.CellService', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        if iNum==4:
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            _log("[-] This is not APT-C-23")

    #------------------------------------------------------------------
    # extract_config : This extracts the C&C information from APT-C-23.
    #------------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if 'update/app/a;'.lower() in cls.get_name().lower():
                _log("[+] It's APT-C-23")
                c2 = []
                string = None
                for method in cls.get_methods():
                    if 'a;-><clinit>()v'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if "http://" in string:
                                    c2.append(string)
                if self.isNotEmpty(c2[0]):
                    _log('[+] Extracting from %s' % (self.apkfile))
                    for CC in c2:
                        _log("[+] Extracted C2: %s" % CC)
                    return True