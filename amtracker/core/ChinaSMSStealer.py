import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for ChinaSMSStealer
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    
'''

class ChinaSMSStealer(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyChinaSMSStealer(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(apkfile)
        szPermissions = " ".join(a.get_permissions())
        matchObj = re.search( r'android\.permission\.INTERNET', szPermissions, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'activity\.MainActivity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szReceivers = "".join(a.get_receivers())
        matchObj = re.search( r'receiver\.SMSReceiver', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szServices = "".join(a.get_services())
        matchObj = re.search( r'service\.SecondService', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        if iNum==4:
            bRes = self.extract_config(apkfile)
            return bRes
        else:
            _log("[-] This is not ChinaSMSStealer")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from MoqHao.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        a = apk.APK(apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if 'com/phone/stop/db/a;'.lower() in cls.get_name().lower():
                c2 = ""
                tmp = []
                string = None
                for method in cls.get_methods():
                    if 'Lcom/phone/stop/db/a;->i()Ljava/lang/String;'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output()
                                if "@" in string:
                                    c2 = string.split(',')[-1].strip(" '")
                                    #print c2
                    elif 'Lcom/phone/stop/db/a;->j()Ljava/lang/String;'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                tmp.append(inst.get_output().split(',')[-1].strip(" '"))
                if self.isNotEmpty(c2):
                    _log('[+] Extracting from %s' % apkfile)
                    _log('[+] Email: [ %s ]' % c2[2:])
                    _log('[+] Password: [ %s ]' % tmp[1][2:])
                    return True