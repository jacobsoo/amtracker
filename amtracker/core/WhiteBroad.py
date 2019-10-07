import re, os, zlib, base64
import lief
import zipfile
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    Hashes for samples:
    7b19fb5ebce5807266ff148a0bc8e82505f53d093e4263eb475ef36ffcb88d4f
    e5db5490b62444943e568ae0eeb72842c5ad9b76d264a560c1864e0b3ffbb399
    e7c81bc21a92188fc4b12740e0e2ec5712098f7ff39d69fcbcd13b8cdf9bf5c3
    3107af27646d5503d7adc1cb0220300c78da2f51db2653c9c3dc68a72aa1cb73
    5277f7d41fbc9f164510e23eb34d9a5138e577687d1d7879eaa6212c470c2bda
    e12af38f0682c9be0169a30c952f8cb83d8e131cf8a583cabeb3fd461399dc51
    4ce6b59da8e716258a8c5842adfce1fe0b711920efa98a646225596c9d5b771a
    7e5d94d48dea8771b72fe4280cebab96e7f73a6647aa70f3536ad5a17f8cbc68
    5dd243b93e58fb92477306b99c4565d499645fbef104e94db4fe4c8f7dfd67a6
'''

class WhiteBroad(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())

    def verifyWhiteBroad(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(apkfile)
        szPackageName = a.get_package()
        if szPackageName=="com.red.rainbow":
            bRes = self.extract_config(self.apkfile)
            return bRes
        elif "com.android.hellon" in szPackageName:
            bRes = self.extract_config2(self.apkfile)
            return bRes
        elif "cn.close.vcl.play" in szPackageName:
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            szPermissions = " ".join(a.get_permissions())
            matchObj = re.search( r'android\.permission\.INTERNET', szPermissions, re.DOTALL|re.UNICODE|re.M|re.I)
            if matchObj:
                iNum += 1
            szActivities = "".join(a.get_activities())
            matchObj = re.search( r'activity\.MainActivity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
            if matchObj:
                iNum += 1
            szReceivers = "".join(a.get_receivers())
            matchObj = re.search( r'receiver\.ShowReceiver', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
            if matchObj:
                iNum += 1
            szServices = "".join(a.get_services())
            matchObj = re.search( r'call\.service\.New1Services', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
            if matchObj:
                iNum += 1
            if iNum==4:
                bRes = self.extract_config(self.apkfile)
                return bRes
            else:
                _log("[-] This is not WhiteBroad")

    def slicer(self, my_str, sub):
        index = my_str.find(sub)
        if index !=-1 :
            return my_str[index:] 

    def ExtractC2(self, szFilename):
        self.szFilename = szFilename
        library = lief.parse(szFilename)
        for segment in library.segments:
            for section in segment.sections:
                C2 = ""
                tmp = ""
                if ".rodata" in section.name:
                    tmp = section.content
                    for c in tmp:
                        C2 += (chr(c))
                    tmp = C2.split('.php')
                    _log("[+] URLs found")
                    for url in tmp:
                        url = self.slicer(url, "http")
                        if '\x00' in url:
                            url = url[:url.find('\x00')]
                            _log("    [+] %s" % url)
                        else:
                            _log("    [+] %s.php" % url)

    #--------------------------------------------------------------------
    # extract_config : This extracts the C&C information from WhiteBroad.
    #--------------------------------------------------------------------
    def extract_config2(self, apkfile):
        bRes = False
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        szFilename = ""
        with zipfile.ZipFile(apkfile, 'r') as f:
            names = f.namelist()
            for filename in names:
                if "libhelper.so" in filename or "libma1sker.so" in filename or "libma2sker.so" in filename or "libma3sker.so" in filename:
                    _log("[+] Found %s" % os.path.basename(filename))
                    f.extract(filename, "C:\\tmp")
                    szFilename = "C:\\tmp\\" + filename.replace('/', '\\')
                    self.ExtractC2(szFilename)
                    return True
        f.close()
        
    #--------------------------------------------------------------------
    # extract_config : This extracts the C&C information from WhiteBroad.
    #--------------------------------------------------------------------
    def extract_config(self, apkfile):
        bRes = False
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if 'Lcom/map/call/config/CompileConfig;'.lower() in cls.get_name().lower():
                c2Found = False
                portFound = False
                c2 = ""
                port = ""
                string = None
                for field in cls.get_fields():
                    string = field.get_init_value().get_value()
                    if 'http://' in string:
                        c2 = string
                        matchObj = re.match( r'http\:\/\/(.*?)\/v1\/api\/', c2, re.M|re.I)
                        if matchObj.group(1):
                            c2 = "http://" + matchObj.group(1)
                        break
                _log("[+] This is WhiteBroad")
                _log('[+] Extracting from %s' % self.apkfile)
                _log('[+] C&C: [ %s ]' % c2)
                return True
            if '/api/ApiManager;'.lower() in cls.get_name().lower():
                c2Found = False
                portFound = False
                c2 = ""
                port = ""
                string = None
                for method in cls.get_methods():
                    if 'ApiManager;->getApi('.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                if 'http://' in str(string):
                                    c2 = string
                                    matchObj = re.match( r'http\:\/\/(.*?)\/v1\/api\/', c2, re.M|re.I)
                                    if matchObj.group(1):
                                        c2 = "http://" + matchObj.group(1)
                                    break
                        _log("[+] This is WhiteBroad")
                        _log('[+] Extracting from %s' % self.apkfile)
                        _log('[+] C&C: [ %s ]' % c2)
                        return True
            if '/common/Constant;'.lower() in cls.get_name().lower():
                c2Found = False
                portFound = False
                c2 = ""
                port = ""
                string = None
                _log("[+] This is WhiteBroad")
                for field in cls.get_fields():
                    if "APPS_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] Apps URL: [ %s ]' % string)
                    elif "CALLLOG_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] Call log URL: [ %s ]' % string)
                    elif "CONFIG_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] Config URL: [ %s ]' % string)
                    elif "CONTACT_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] Contact Url: [ %s ]' % string)
                    elif "HEARTBEAT_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] Heartbeat URL: [ %s ]' % string)
                    elif "IP_ADDRESS" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] IP Address: [ %s ]' % string)
                    elif "LOCATION_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] Location URL: [ %s ]' % string)
                    elif "LOGS_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] Logs URL: [ %s ]' % string)
                    elif "REGIST_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] Regist URL: [ %s ]' % string)
                    elif "SMS_URL" in field.get_name():
                        string = field.get_init_value().get_value()
                        _log('[+] SMS URL: [ %s ]' % string)
                    return True