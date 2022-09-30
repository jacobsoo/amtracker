import re, os, zlib, base64
import binascii
from typing import List
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from amtracker.common.out import _log
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.decompiler.decompiler import DecompilerJADX

'''
    Hashes for samples:
    65c655663b9bd756864591a605ab935e52e5295735cb8d31d16e1a6bc2c19c28
    ab345951a3e673aec99f80d39fa8f9cdb0d1ac07e0322dae3497c237f7b37277
'''

class Xenomorph(object):
    def __init__(self):
        self.name = None
        self.path = None
        self.apkfile = None

    #---------------------------------------------------
    # isNotEmpty : Checks whether string is empty
    #---------------------------------------------------
    def isNotEmpty(self, s):
        return bool(s and s.strip())
    
    #----------------------------------------------------
    # isBase64 : Checks whether string is Base64 Encoded
    #----------------------------------------------------
    def isBase64(self, s):
        try:
            if isinstance(s, str):
                # If there 's any unicode here, an exception will be thrown and the function will return false
                sb_bytes = bytes(s, 'ascii')
            elif isinstance(s, bytes):
                sb_bytes = s
            else :
                raise ValueError("Argument must be string or bytes")
            return base64.b64encode(base64.b64decode(sb_bytes, validate = True)) == sb_bytes
        except Exception:
            return False

    def verifyXenomorph(self, apkfile):
        self.apkfile = apkfile
        iNum = 0
        a = apk.APK(apkfile)
        szPermissions = " ".join(a.get_permissions())
        matchObj = re.search( r'android\.permission\.INTERNET', szPermissions, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szActivities = "".join(a.get_activities())
        matchObj = re.search( r'MainActivity', szActivities, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szReceivers = "".join(a.get_receivers())
        matchObj = re.search( r'\.services\.SmsReceiver', szReceivers, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        szServices = "".join(a.get_services())
        matchObj = re.search( r'\.services\.KingService', szServices, re.DOTALL|re.UNICODE|re.M|re.I)
        if matchObj:
            iNum += 1
        if iNum==4:
            bRes = self.extract_config(self.apkfile)
            return bRes
        else:
            _log("[-] This is not Xenomorph")

    def isValidDomain(self, str):
        # Regex to check valid
        # # domain name. 
        regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
        
        # Compile the ReGex
        p = re.compile(regex)
    
        # If the string is empty
        # return false
        if (str == None):
            return False
    
        # Return if the string
        # matched the ReGex
        if(re.search(p, str)):
            return True
        else:
            return False

    #------------------------------------------------------------------
    # extract_config : This extracts the C&C information from Xenomorph.
    #------------------------------------------------------------------
    def extract_config(self, apkfile):
        self.apkfile = apkfile
        a = apk.APK(self.apkfile)
        d = dvm.DalvikVMFormat(a.get_dex())
        for cls in d.get_classes():
            if 'services/KingService' in cls.get_name():
                _log("[+] It's Xenomorph")
                bRes = True
        c2 = []
        if bRes:
            for cls in d.get_classes():
                string = None
                for method in cls.get_methods():
                    if(str(method).lower):
                        for inst in method.get_instructions():
                            if inst.get_name() == 'const-string':
                                string = inst.get_output().split(',')[-1].strip(" '")
                                bRes = self.isBase64(string)
                                #print("{} : {}".format(string, bRes))
                                if bRes is True:
                                    data = base64.b64decode(string)
                                    try:
                                        szCheck = chr(data[8]) + chr(data[9]) + chr(data[10])
                                        # key = <rc4 key>
                                        key = chr(data[0]) + chr(data[1]) + chr(data[2])+ chr(data[3]) + chr(data[4]) + chr(data[5]) + chr(data[6]) + chr(data[7])
                                        if szCheck==":::":
                                            #key = "<rc4 key>"
                                            
                                            S = list(range(256))
                                            j = 0
                                            out = []
                                            
                                            #KSA Phase
                                            for i in range(256):
                                                j = (j + S[i] + ord( key[i % len(key)] )) % 256
                                                S[i] , S[j] = S[j] , S[i]
                                                
                                            #PRGA Phase
                                            i = j = 0
                                            for char in data[11:]:
                                                i = ( i + 1 ) % 256
                                                j = ( j + S[i] ) % 256
                                                S[i] , S[j] = S[j] , S[i]
                                                out.append(chr((char) ^ S[(S[i] + S[j]) % 256]))
                                            decrypted_text = ''.join(out)
                                            bRes= self.isValidDomain(decrypted_text)
                                            if bRes and "android." not in decrypted_text and "com.miui." not in decrypted_text and "applications." not in decrypted_text and "uioverrides." not in decrypted_text:
                                                #_log("[+] Detected valid Encrypted Text : {}".format(data))
                                                #_log("[+] Decrypted Text (Potential C2): {}".format(decrypted_text))
                                                c2.append(decrypted_text)
                                            decrypted_text = ""
                                    except Exception:
                                        continue
            if len(c2)>1:
                _log('[+] Extracting from %s' % self.apkfile)
                for i in range(len(c2)):
                    _log('[+] C&C : [ %s ]' % c2[i])
                return True
                                            
                                    