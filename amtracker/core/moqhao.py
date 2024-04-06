import re, os, zlib, base64
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log

'''
    C&C and payload extractor for Moqhao
    by Jacob Soo Lead Re (jacob.soo@starlabs.sg)
    
    This doesn't cater for all the different variants.
    There are various variants which i haven't figured a better regex for it.
    --> Services contain "org.BeroMainService"
    --> some of the older variants as discussed here, https://securelist.com/roaming-mantis-part-iv/90332/
'''

class moqhao(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    def verifyMoqhao(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(apkfile)
        szPermissions = " ".join(a.get_permissions())
        matchObj = re.search( r'android\.permission\.INTERNET', szPermissions, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'org\.[a-zA-Z]{1,3}bgsActivity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szReceivers = "".join(a.get_receivers())
        matchObj = re.search( r'org\.[a-zA-Z]{1,3}vtyReceiver', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szServices = "".join(a.get_services())
        matchObj = re.search( r'org\.[a-zA-Z]{1,3}rMainService', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        if iNum==4:
            szPayload = a.get_files()
            for actualPayload in szPayload:
                searchObj = re.search( r'assets/[a-d]/(.*?)', actualPayload, re.DOTALL|re.UNICODE|re.M|re.I)
                if searchObj:
                    bRes = self.extract_config(apkfile, actualPayload)
                    return bRes
        else:
            _log("[-] This is not Moqhao")
    
    #------------------------------------------------------------------
    # extract_c2_accounts : This extracts the C&C accounts from MoqHao.
    #------------------------------------------------------------------
    def extract_c2_accounts(self, strings: List[str]):
        print(strings)
        accounts = [x for x in strings if re.match(r"^[a-z]+\|.+", x)]
        if len(accounts) != 1:
            return []

        urls = []
        for account in accounts[0].split("|")[1:]:
            name, provider = account.split("@")
            if provider == "youtube":
                urls.append("[+] https://m.youtube.com/channel/{}/about".format(name))
            elif provider == "ins":
                urls.append("[+] https://www.instagram.com/{}/".format(name))
            elif provider == "GoogleDoc" or provider == "GoogleDoc2":
                urls.append("[+] https://docs.google.com/document/d/{}/mobilebasic".format(name))
            elif provider == "vk":
                urls.append("[+] https://m.vk.com/{}?act=info".format(name))
            elif provider == "blogger":
                urls.append("[+] https://www.blogger.com/profile/{}".format(name))
        return urls

    #-----------------------------------------------------------------
    # extract_config : This extracts the C&C information from MoqHao.
    #-----------------------------------------------------------------
    def extract_config(self, apkfile, actualPayload):
        a = apk.APK(apkfile)
        payload_bytes = a.get_file(actualPayload)
        dec_z = zlib.decompress(payload_bytes[4:])            # open.skip(4);
        dec_b = base64.b64decode(dec_z)
        dex = dvm.DalvikVMFormat(base64.b64decode(dec_z))
        payload_dec = os.path.basename(actualPayload)+".dec"
        with open(payload_dec,"wb") as fp:
            fp.write(dec_b)
            _log("[+] Payload is extracted as {}".format(payload_dec))
        urls = self.extract_c2_accounts(dex.get_strings())
        for url in urls:
            _log(url)
        for cls in dex.get_classes():
            if '/loader$al;'.lower() in cls.get_name().lower():
                credentials = []
                string = None
                for method in cls.get_methods():
                    if 'loader$al;->run()v'.lower() in str(method).lower():
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                credentials.append(string)
                        iNumber = len(credentials)
                        _log('[+] Extracting credentials from %s' % payload_dec)
                        _log('[+] Email address : %s' % credentials[iNumber-2])
                        _log('[+] Email password : %s' % credentials[iNumber-1])
                        return True