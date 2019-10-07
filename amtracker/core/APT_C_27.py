import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    Hashes for samples:
    0713ff7bb8d9dc5bbe865176e6fe70fe6983b90f7f4323171f2fa3881d02b422
    041b9066f42b78c5f2c9ff25a3bba3155a21c21fa0ee55aea510f456b3bc1847
    caf0f58ebe2fa540942edac641d34bbc8983ee924fd6a60f42642574bbcd3987
    b15b5a1a120302f32c40c7c7532581ee932859fdfb5f1b3018de679646b8c972
    2d0a56a347779ffdc3250deadda50008d6fae9b080c20892714348f8a44fca4b
'''

class APT_C_27(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyAPT_C_27(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(apkfile)
        szPermissions = " ".join(a.get_permissions())
        matchObj = re.search( r'android\.permission\.INTERNET', szPermissions, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'\.MainActivity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szReceivers = "".join(a.get_receivers())
        matchObj = re.search( r'\.Syst[e]{0,1}mUpt[e]{0,2}n', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szServices = "".join(a.get_services())
        matchObj = re.search( r'\.N[e]{0,1}tS[e]{0,1}rvice', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        if iNum==4:
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            _log("[-] This is not APT-C-27")

    #------------------------------------------------------------------
    # extract_config : This extracts the C&C information from APT-C-27.
    #------------------------------------------------------------------
    def extract_config(self, apkfile):
        bRes = False
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if '/PcketPrvidr;'.lower() in cls.get_name().lower() or '/PacketProvider;'.lower() in cls.get_name().lower():
                _log("[+] It's APT-C-27")
                _log("[+] Extracting from %s" % self.apkfile)
                c2 = ""
                szTemp = ""
                szNum = ""
                port = ""
                string = None
                for method in cls.get_methods():
                    if ';-><clinit>()v'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                szTemp = string
                            if inst.get_name() == 'sput-object':
                                if ";->IP" in inst.get_output():
                                    c2 = szTemp
                            if inst.get_name() == 'const/16':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                szNum = string
                            if inst.get_name() == 'sput':
                                if ";->PORT" in inst.get_output():
                                    port = szNum
                if self.isNotEmpty(c2):
                    _log("[+] Extracted C2: %s:%s" % (c2, port))
                    bRes = True
                return bRes