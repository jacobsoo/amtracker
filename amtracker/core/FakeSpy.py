import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for FakeSpy
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    Hashes for samples:
    a8e7f53427fff29d46b43efe508cd046537b09324b6b0574c3e15b863b4136a1
    51793a9bc21e8235266ec150cb1152e94104b95c364ee9544bc231447c3d0002
    4c41274f3927577cff271de57b3de3a464c11add7245d272877bc676a369dd3b
    fa70929f95894c19dae0b58666204251d076b0b1a81a23529847f679135e2ca4
    b2b43c197af5196c566baeec8e64aa4bb0a922d3a05d5f5c5c3e752b106093f4
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
            if 'MyService$ReThread;'.lower() in cls.get_name().lower():
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