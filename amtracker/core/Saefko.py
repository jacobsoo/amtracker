import re, os, zlib, base64
import urllib
from urllib.parse import urlparse
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for Saefko
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    References : https://www.zscaler.com/blogs/research/saefko-new-multi-layered-rat
    
    Hashes for samples:
    fb94d34523b06ccea3227bf2e33b5a3ab75822b6fd5257218dd6ce9ada163ae4
    6260f500a0847ecebe34f4fcbe89cf5f9708669dabe7bb1dfa6ca0d2f3cbd107
    08cea5ba0e699b6bc74e8932ec5d3f6c6d6dac0da7d05af90dc94226fc8fa9a2
    83ebcc9ac17eba188c4083ad1cc8d8ab7f243e7e22b55a677f1f32c577a2f3f8
    1ef3612c8b83307af68661583214643aaca748a4b51913b253835dfe92f6c864
'''

class Saefko(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifySaefko(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szPackageName = a.get_package()
        if "com.sas.seafkoagent.seafkoagent" in szPackageName:
            bRes = self.extract_config(apkfile)
            if bRes == True:
                return True
            else:
                _log("[-] This is not Saefko")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from Saefko.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        string = ""
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if 'Lcom/sas/seafkoagent/seafkoagent/GLOBALS;'.lower() in cls.get_name().lower():
                c2 = ""
                serverpass = ""
                string = None
                for field in cls.get_fields():
                    if "SERVER_PASS" in field.get_name():
                        string = field.get_init_value().get_value()
                        serverpass = string
                    elif "SERVER_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        c2 = string
                if self.isNotEmpty(c2):
                    parsed_uri = urlparse(c2)
                    result = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
                    _log('[+] Extracting from %s' % self.apkfile)
                    _log('[+] C&C: [ %s ]' % c2)
                    _log('[+] Server password: [ %s ]' % serverpass)
                    _log('[+] The DB file is most likely at [ %s ]' % (result + "seafko_db.db"))
                    return True