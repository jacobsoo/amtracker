import re, os, zlib, base64
from typing import List
import struct
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from amtracker.common.out import _log

'''
    C&C and payload extractor for APT41 Android Mobile Malware
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    1107200102a22114f3e8affa7409d0d1faa521b2bf20ff58d33a00faac22ed8f
    391d22d89fc8eddfd3691e846d5e183c5925754443cacc0ba6a252858f290735
    48e3f32e770f01b428f1c88227230623ab5477d0243694e62a4cb6fee0036800
    4e5379745f10a1843e7205a61aad39bfa783a98dd972960fd1d3bc7b58361b2b
    b66847d571e471ac78ffa11a82dded5ac6d2f52b25304adbfab90716d22c0905

    
    This doesn't cater for all the different variants.
    There are various variants which i haven't been tracking actively.
    --> https://www.lookout.com/threat-intelligence/article/wyrmspy-dragonegg-surveillanceware-apt41
'''

class APT41(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())
    
    @staticmethod
    def printIntentFilters(itemtype, name, apkfile):
        a = apk.APK(apkfile)
        print('\t' + name + ':')
        for action,intent_name in a.get_intent_filters(itemtype, name).items():
            print('\t\t' + action + ':')
            for intent in intent_name:
                print('\t\t\t' + intent)
        return

    def verifyAPT41(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(self.apkfile)
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'\.MainActivity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szReceivers = "".join(a.get_receivers())
        matchObj = re.search( r'\.BootReceiver', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        receivers = a.get_receivers()
        for receiver in receivers:
            for intent_name in a.get_intent_filters('receiver', receiver).items():
                matchObj = re.search( r'android\.intent\.action\.RM', str(intent_name), re.DOTALL|re.UNICODE|re.M|re.I)
                if matchObj:
                    iNum += 1
        if iNum==3:
            _log("[+] This is likely APT41")
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            _log("[+] This is likely not APT41")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from APT41.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        try:
            a = apk.APK(apkfile)
            szPackageName = a.get_package()
            manifest_str = a.get_android_manifest_axml().get_xml()
            matchPass = re.search( r':name="p" .*?:value="(.*?)\"\/\>', manifest_str.decode('utf-8'), re.DOTALL|re.UNICODE|re.M|re.I)
            matchVersion = re.search( r':name="v" .*?:value="(.*?)\"\/\>', manifest_str.decode('utf-8'), re.DOTALL|re.UNICODE|re.M|re.I)
            matchServer = re.search( r':name="u" .*?:value="(.*?)\"\/\>', manifest_str.decode('utf-8'), re.DOTALL|re.UNICODE|re.M|re.I)
            matchCustomId = re.search( r':name="CustomId" .*?:value="(.*?)\"\/\>', manifest_str.decode('utf-8'), re.DOTALL|re.UNICODE|re.M|re.I)
            string = ""
            a = apk.APK(self.apkfile)
            package = a.get_package()
            dx = analysis.Analysis()
            for d in a.get_all_dex():
                d1 = dvm.DalvikVMFormat(d)
                for cls in d1.get_classes():
                    matchObj = re.search( r'\/Root;', cls.get_name().lower(), re.DOTALL|re.UNICODE|re.M|re.I)
                    if matchObj is not None:
                        #print(cls)
                        c2 = []
                        string = None
                        for method in cls.get_methods():
                            #print(method)
                            if ';->DownRootPlan('.lower() in str(method).lower():
                                for inst in method.get_instructions():
                                    #print("{} : {}".format(inst.get_name(), inst.get_output()))
                                    if inst.get_name() == 'const-string':
                                        string = inst.get_output().split(',')[-1].strip(" '")
                                        #print(string)
                                        if "http://" in string:
                                            c2.append(string)
                                if len(c2)>0:
                                    _log('[+] Extracting from %s' % self.apkfile)
                                    _log('[+] Server URL : [ %s ]' % matchServer[1])
                                    _log('[+] Password : [ %s ]' % matchPass[1])
                                    _log('[+] Version : [ %s ]' % matchVersion[1])
                                    _log('[+] Custom ID : [ %s ]' % matchCustomId[1])
                                    for i in range(len(c2)):
                                        _log('[+] C&C : [ %s ]' % c2[i])
            return True
        except struct.error:
            _log("[-] Possibly corrupted APK")