import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for FakeSpy
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    a4802bceaa9bfe337460d5935626b85d5f497a0f5d13afe0539925f4e0748c5f
    fc3a6bc2dec16aa4f6b3ddcd88718ec2b6b03d5ea8e784ed03bc3bb70d323a40
    dff641baafbc26af4a7afc804d393aa67809e1b6e0f6b8c5dfb7108b34dc043f
    3585853bc1d6448810fae2fdd511b180294cb6f82d4caebbc099ac2e3a544c9b
    c6f926b31d991ec9b26f83908d3fcf64c5f764ec1df12a6cf34af8c09dbf03f6
'''

class FakeSpy(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyFakeSpy(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(self.apkfile)
        szPermissions = " ".join(a.get_permissions())
        matchObj = re.search( r'android\.permission\.INTERNET', szPermissions, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'\.MainActivity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szReceivers = "".join(a.get_receivers())
        matchObj = re.search( r'\.MyReceiver', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szServices = "".join(a.get_services())
        matchObj = re.search( r'\.M[e|y]Service', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        if iNum==4:
            bRes = self.extract_config(apkfile)
            return bRes
        else:
            _log("[-] This is not FakeSpy")

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from FakeSpy.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        szCONFIG_URL = ""
        szIP_ADDRESS = ""
        szLOGS_URL = ""
        for cls in d.get_classes():
            if 'Lcom/example/dew18/myapplication/MyService$ReThread;'.lower() in cls.get_name().lower():
                c2 = ""
                string = None
                for method in cls.get_methods():
                    if 'MyService$ReThread;->run()V'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if "http://" in string:
                                    c2 = string[:-15]
                if self.isNotEmpty(c2):
                    c2 = c2.replace("u'", "")
                    DB_Creds_Page = c2 + "common/Define.php.bak"
                    C2_Creds_Page = c2 + "adminpage.php"
                    try:
                        r = requests.get(DB_Creds_Page)
                        DB_Creds = r.text
                        r = requests.get(C2_Creds_Page)
                        matchObj = re.search( r'<span id2=.* > (.*?)<\/span><\/td><td><span pass2=.*> (.*?)<\/span><\/td><td><span appNum', r.text, re.M|re.I)
                        username = matchObj.group(1)
                        password = matchObj.group(2)
                        _log('Extracting from %s' % self.apkfile)
                        _log('C&C: [ %s, %s ]' % (c2 + "login.php", c2+"adminpage.php"))
                        _log('C&C Username: [ %s ]' % username)
                        _log('C&C Password: [ %s ]' % password)
                        _log('DB credentials: \n%s' % DB_Creds)
                        return True
                    except:
                        _log('Extracting from %s' % apkfile)
                        _log('C&C: [ %s,%s ]' % (DB_Creds_Page, C2_Creds_Page))
                        return True
            elif 'MeService$ReThread;'.lower() in cls.get_name().lower():
                c2 = ""
                string = None
                for method in cls.get_methods():
                    if 'MeService$ReThread;->run()V'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if "http://" in string:
                                    c2 = string[:-15]
                if self.isNotEmpty(c2):
                    c2 = c2.replace("u'", "")
                    DB_Creds_Page = c2 + "common/Define.php.bak"
                    C2_Creds_Page = c2 + "adminpage.php"
                    try:
                        r = requests.get(DB_Creds_Page)
                        DB_Creds = r.text
                        r = requests.get(C2_Creds_Page)
                        matchObj = re.search( r'<span id2=.* > (.*?)<\/span><\/td><td><span pass2=.*> (.*?)<\/span><\/td><td><span appNum', r.text, re.M|re.I)
                        username = matchObj.group(1)
                        password = matchObj.group(2)
                        _log('Extracting from %s' % self.apkfile)
                        _log('C&C: [ %s, %s ]' % (c2 + "login.php", c2+"adminpage.php"))
                        _log('C&C Username: [ %s ]' % username)
                        _log('C&C Password: [ %s ]' % password)
                        _log('DB credentials: \n%s' % DB_Creds)
                        return True
                    except:
                        _log('Extracting from %s' % apkfile)
                        _log('C&C: [ %s,%s ]' % (DB_Creds_Page, C2_Creds_Page))
                        return True
            elif "Lorg/red/cute/common/Constant;".lower() in cls.get_name().lower():
                c2 = ""
                string = None
                for field in cls.get_fields():
                    if "CONFIG_URL".lower() in str(field).lower():
                        szCONFIG_URL = field.get_init_value().get_value()
                    elif "IP_ADDRESS".lower() in str(field).lower():
                        szIP_ADDRESS = field.get_init_value().get_value()
                    elif "LOGS_URL".lower() in str(field).lower():
                        szLOGS_URL = field.get_init_value().get_value()
                if szCONFIG_URL:
                    _log('Extracting from %s' % apkfile)
                    _log('C&C: [ %s ]' % szIP_ADDRESS)
                    _log('C&C Config URL: [ %s ]' % szCONFIG_URL)
                    _log('C&C Logs URL : [ %s ]' % szLOGS_URL)
                    return True