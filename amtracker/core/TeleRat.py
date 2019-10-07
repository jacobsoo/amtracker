import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    Hashes for samples:
    710e793d606f5633bc6cebb47356fa5632e02d017f08332ec0000ac5eb358b3d
    c6e0e4b54020b4b452ac25d8f26194cde51dfb2df18e8dcab07bd4acf6245ffe
    e121d4b8fe5c528aaca30149326111ee695350f22b055e3e4e1dfc7fafddf740
    19890de01aa82eccbce329e8ce0fbae985b8e07273141f3e78f4a942630bdb14
    63308d8ef2d7b124dc6923e1b43816c0398ba22fec7fd2e640a4aa229eca15d6
'''

class TeleRat(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())
    
    def verifyTeleRat(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szPackageName = a.get_package()
        if szPackageName=="b4a.example":
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            _log("[-] This is not TeleRat")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from TeleRat.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        bTeleRat = False
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if '/servis;'.lower() in cls.get_name().lower():
                _log("[+] This is TeleRat.")
                bTeleRat = True
                c2 = ""
                string = None
                for method in cls.get_methods():
                    if 'servis;->_service_start(L'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if "upload_file.php" in string:
                                    c2 = string
                for method in cls.get_methods():
                    if 'servis;->_send_message(Ljava/lang/String;)'.lower() in str(method).lower():
                        TeleGramInfo = []
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                TeleGramInfo.append(string)
                if self.isNotEmpty(c2):
                    _log('[+] Extracting from %s' % self.apkfile)
                    _log('[+] C&C : [ %s ]' % c2)
                    _log('[+] Telegram Webhook : [ %s ]' % TeleGramInfo[1])
                    _log('[+] ChatID : [ %s ]' % TeleGramInfo[3])
                    return True
        if bTeleRat==False:
            _log("[-] This is not TeleRat")