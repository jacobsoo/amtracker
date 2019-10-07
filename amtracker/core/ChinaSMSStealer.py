import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for ChinaSMSStealer
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    ca9fcd32fe770cd5f3427100de15a93bda710aa3034c5daa22e90b5a2abf8abd
    4eb770e004f6df8a696a63145be4531be66d36492f3dccfc6a0782b1eb336a46
    fe00cfa0f75e855282886658930c7048fef7530989198d4e6a7620bf2d274b77
    ba0bfb33123796d452e86a95da3e79dea2c51f736332c16878861c3e37baac30
    47ebd40226d34e808b231f9948c04d648f1234776b8438c2d8dd76bf9089f517
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