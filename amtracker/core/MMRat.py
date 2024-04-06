import re, os, zlib, base64
import urllib
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from amtracker.common.out import _log

'''
    C&C and payload extractor for MMRat
    by Jacob Soo (jacob.soo@starlabs.sg)
    
    Reference:
    https://www.trendmicro.com/en_za/research/23/h/mmrat-carries-out-bank-fraud-via-fake-app-stores.html

    Hashes for samples:
    ac2f69c3b9400ee2eec035b54ce902be77a5b39dc2446a7f61bd087cde954982
    d06fc998c4aa6a7abd294aa3e5edb566ef2097f897c23c5fe0b34a2c2ea3bd46
    124d3a55770da5f7eb24291010e89c991828147758550b1c9ec68ccab5335b0b
    51847406cf995ff0d6dabcfd15ba1303051ced3dbf68106a5758bbabc21942db
    68abbf83f53fdcbd04e0d39dc2152b0c31ef663c0b042cc1e918836cf2b69f5e
'''

class MMRat(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyMMRat(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'com\.mm\.user\.ui\.activity\.WebViewActivity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj==None:
            _log("[-] This is not MMRat")
            return False
        else:
            _log("[+] This is likely MMRat")
            bRes = self.extract_config(apkfile)
            if bRes == True:
                return True

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from MMRat.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        string = ""
        a = apk.APK(self.apkfile)
        package = a.get_package()
        dx = analysis.Analysis()
        for d in a.get_all_dex():
            d1 = dvm.DalvikVMFormat(d)
            for cls in d1.get_classes():
                matchObj = re.search( r'com\/mm\/user\/utils\/[a-z$]{1,5};', cls.get_name().lower(), re.DOTALL|re.UNICODE|re.M|re.I)
                if matchObj is not None:
                    c2 = []
                    string = None
                    for method in cls.get_methods():
                        if ';-><init>()V'.lower() in str(method).lower():
                            for inst in method.get_instructions():
                                if inst.get_name() == 'const-string':
                                    string = inst.get_output().split(',')[-1].strip(" '")
                                    #print(string)
                                    if "rtsp:" in string:
                                        c2.append(string)
                            if len(c2)>0:
                                _log('[+] Extracting from %s' % self.apkfile)
                                for i in range(len(c2)):
                                    _log('[+] C&C : [ %s ]' % c2[i])
                                return True