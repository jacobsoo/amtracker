import re, os, zlib, base64
import datetime
import hashlib
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    Hashes for samples:
    136cbcacf832aca13f7a9ec442079b1a504a6d3d3f720c6fec547f855ae08cea
    d62705186c488bb26fccdb1404931223a887004fd6704ac1483e599a15e92792
    83a4718fd650f78bf1aed4a5eb560950aab8bc2ea432598402c38568f7e462ab
    8304a6d1410629d7bc79b78f7f719530be0be764a4e0527bb3a3cf456ce2036a
    4ce9fee0295cbb745c37e0f1da085ef500159b5bd9e5ec8c986e9cce38882c50
    6478764346de677ed2a6f8c54daad96b6bdccb96449787c1db66a32f62175756
    c90b3f9f0b226857fa8ec270032f4f1595579e9487e87a3ecad714a1205695f4
'''

class CapraRAT(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())
    
    def verifyCapraRAT(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(apkfile)
        szPermissions = " ".join(a.get_permissions())
        matchObj = re.search( r'android\.permission\.INTERNET', szPermissions, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'\.Main2Activity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szReceivers = "".join(a.get_receivers())
        matchObj = re.search( r'\.BootUpReceiver', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szServices = "".join(a.get_services())
        matchObj = re.search( r'\.TCPClient', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        if iNum==4:
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            _log("[-] This is not CapraRAT")

    def extract_config(self, apkfile):
        try:
            szTemp = ""
            c2Found = []
            c2 = []
            iPorts = []
            self.apkfile = apkfile
            a = apk.APK(self.apkfile)
            d = dvm.DalvikVMFormat(a.get_dex())
            for cls in d.get_classes():
                if "/setting;" in cls.get_name().lower():
                    _log("[+] It's CapraRAT")
                    for method in cls.get_methods():
                        if ';-><clinit>()v'.lower() in str(method).lower():
                            for inst in method.get_instructions():
                                if inst.get_name() == 'const-string':
                                    string = inst.get_output().split(',')[-1].strip(" '")
                                    szTemp = string
                                if inst.get_name() == 'sput-object':
                                    if "SERVERIP" in inst.get_output():
                                        c2Found = szTemp.split("-")
                                        for item in c2Found:
                                            c2.append(item)
                                if inst.get_name() == 'const/16':
                                    string = inst.get_output().split(',')[-1].strip(" '")
                                    szNum = string
                                if inst.get_name() == 'sput':
                                    if "SERVERPORT" in inst.get_output():
                                        iPorts.append(szNum)
            if len(c2)>1:
                _log('[+] Extracting from %s' % self.apkfile)
                for i in range(len(c2)):
                    _log('[+] C2 : [ {} ]'.format(c2[i]))
                for i in range(len(iPorts)):
                    _log('[+] Ports : [ {} ]'.format(iPorts[i]))
                return True
        except:
            pass