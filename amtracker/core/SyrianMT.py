import re, os, zlib, base64
from typing import List
import struct
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for Syrian Mobile Malware
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    This doesn't cater for all the different variants.
    There are various variants which i haven't been tracking actively.
    --> Package names contain :
        - com.Google.Gmail
        - GOOD.BYE.GOOGLE
        - com.android.tester
        - com.syria.tel
        - syria.tel.ctu
        - com.syriatel.ctu
    --> https://blog.lookout.com/nation-state-mobile-malware-targets-syrians-with-covid-19-lures
'''

class SyrianMT(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifySyrianMT(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szPackageName = a.get_package()
        if szPackageName=="com.Google.Gmail" or szPackageName=="GOOD.BYE.GOOGLE" or szPackageName=="com.android.tester" or szPackageName=="com.syria.tel" or szPackageName=="syria.tel.ctu" or szPackageName=="com.syriatel.ctu":
            _log("  [+] Package Name : %s" % (szPackageName))
            _log("  [+] This is likely a Syrian Mobile Trojan")
            bRes = self.extract_config(apkfile)
            if bRes == True:
                return True
            else:
                _log("[-] This is not Syrian Mobile Trojan")
    
    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from MoqHao.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        try:
            a = apk.APK(apkfile)
            szPackageName = a.get_package()
            r = a.get_android_resources()
            szHost = ''
            szHost = r.get_string(szPackageName, "h", "\x00\x00")
            szPort = ''
            szPort = r.get_string(szPackageName, "p", "\x00\x00")
            if szHost is not None:
                if self.isNotEmpty(szHost[1]):
                    _log('  [+] Extracting from %s' % (self.apkfile))
                    _log('  [+] C&C: [ %s:%s ]' % (szHost[1], szPort[1]))
                    return True
        except struct.error:
            _log("[-] Possibly corrupted APK")