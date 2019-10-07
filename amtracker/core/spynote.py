import re, os, zlib, base64
import datetime
import hashlib
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    Hashes for samples:
    fb0cf4974730c8e36a4f66117c8ef9e049a03e83f77d46161c8d0f6fae3e3e71
    eed2d0e942097241e7a8f8d55bfc1b5a1184367e619909c3118420fa9e4e575f
    4e457a942c5ecad32ebeb0825dd28129681ad3ee013e8c35d8bc89ca8206442b
    cf659e92d8a4a344d6968b137d3bb2a976ac8ef7905c6e312aea45fc35a38cfe
    d40a1ff6dddb310e6abd8b0c69f092db5c121aab4e2ff71936d06a82e376a7a7
'''

class spynote(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())
    
    def verifySpyNote(self, apkfile):
        try:
            self.apkfile = apkfile
            iNum = 0
            a = apk.APK(self.apkfile)
            szPackageName = a.get_package()
            if szPackageName=="yps.eton.application":
                _log("[+] This is SpyNote")
                d = dvm.DalvikVMFormat(a.get_dex())
                r = a.get_android_resources()
                app_name = ''
                app_name = r.get_string(szPackageName, "host", "\x00\x00")
                if app_name is not None:
                    if self.isNotEmpty(app_name[1]):
                        dat = app_name[1].split(",")
                        _log('[+] Extracting from %s' % (self.apkfile))
                        _log('[+] C&C: [ %s:%s ]' % (dat[0], dat[1]))
                        return True
            else:
                _log("[-] This is not SpyNote v2")
        except:
            pass