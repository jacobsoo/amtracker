import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    Hashes for samples:
    3bfec096c4837d1e6485fe0ae0ea6f1c0b44edc611d4f2204cc9cf73c985cbc2
    dff2e39b2e008ea89a3d6b36dcd9b8c927fb501d60c1ad5a52ed1ffe225da2e2
    26de4265303491bed1424d85b263481ac153c2b3513f9ee48ffb42c12312ac43
    9af8a93519d22ed04ffb9ccf6861c9df1b77dc5d22e0aeaff4a582dbf8660ba6
    6b4d271a48d118843aee3dee4481fa2930732ed7075db3241a8991418f00d92b
'''

class MuddyWater(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyMuddyWater(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(apkfile)
        szPermissions = " ".join(a.get_permissions())
        matchObj = re.search( r'android\.permission\.INTERNET', szPermissions, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'client\.Main', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szReceivers = "".join(a.get_receivers())
        matchObj = re.search( r'receiver\.SmsReceiver', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szServices = "".join(a.get_services())
        matchObj = re.search( r'client\.Client', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        if iNum==4:
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            _log("[-] This is not MuddyWater")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from MuddyWater.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        bRes = False
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if '/titan/appUtil/utils/AppField;'.lower() in cls.get_name().lower():
                _log("[+] It's MuddyWater")
                _log("[+] Extracting from %s" % self.apkfile)
                c2 = []
                string = None
                for field in cls.get_fields():
                    if "SERVER_IP" in field.get_name():
                        string = field.get_init_value().get_value()
                        c2.append(string)
                if self.isNotEmpty(c2[0]):
                    for CC in c2:
                        _log("[+] Extracted C2: %s" % CC)
                        bRes = True
                for field in cls.get_fields():
                    if "SERVER_PORT" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log("[+] Port: %s" % string)
                return bRes