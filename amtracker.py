#!/usr/bin/python

__author__ = "Jacob Soo Lead Re"
__version__ = "0.1"

import zipfile, sys, os, re
import base64, zlib, urllib
import yara
import argparse
from typing import List
from sys import argv
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.decompiler.decompiler import DecompilerJADX
from amtracker.core.BladeHawk import BladeHawk
from amtracker.core.AhMyth import AhMyth
from amtracker.core.AndroRat import AndroRat
from amtracker.core.APT_C_23 import APT_C_23
from amtracker.core.APT_C_27 import APT_C_27
from amtracker.core.BankBot import BankBot
from amtracker.core.CapraRAT import CapraRAT
from amtracker.core.ChinaSMSStealer import ChinaSMSStealer
from amtracker.core.Dendroid import Dendroid
from amtracker.core.EventBot import EventBot
from amtracker.core.FakeSpy import FakeSpy
from amtracker.core.FlexBotnet import FlexBotnet
from amtracker.core.moqhao import moqhao
from amtracker.core.Saefko import Saefko
from amtracker.core.SandroRat import SandroRat
from amtracker.core.spynote import spynote
from amtracker.core.SyrianMT import SyrianMT
from amtracker.core.TeleRat import TeleRat
from amtracker.core.Triout import Triout
from amtracker.core.Vamp import Vamp
from amtracker.core.MuddyWater import MuddyWater
from amtracker.core.WhiteBroad import WhiteBroad
from amtracker.core.Xenomorph import Xenomorph



android_family = ["BladeHawk", "AndroRat", "AhMyth", "apt-c-23", "apt-c-27", "BankBot", "CapraRAT", "ChinaSMSStealer", "Dendroid", "EventBot", "FakeSpy", "FlexBotnet", "moqhao", "MuddyWater", "Saefko", "SandroRat", "spynote", "SyrianMT", "TeleRat", "Triout", "Vamp", "WhiteBroad", "Xenomorph"]

#---------------------------------------------------
# isNotEmpty : Checks whether string is empty
#---------------------------------------------------
def isNotEmpty(s):
    return bool(s and s.strip())

#---------------------------------------------------
# _log : Prints out logs for debug purposes
#---------------------------------------------------
def _log(s):
    print(s)

#-------------------------------------------------------------
# check_apk_file : Shitty Check whether file is a apk file.
#-------------------------------------------------------------
def check_apk_file(apk_file):
    bJar = False
    try:
        zf = zipfile.ZipFile(apk_file, 'r')
        lst = zf.infolist()
        for zi in lst:
            fn = zi.filename
            if fn.lower()=='androidmanifest.xml':
                bJar = True
                return bJar
    except:
        return bJar

#------------------------------------------------------------------------
# verifyMalware : This verify what android family this sample belongs to.
#------------------------------------------------------------------------
def verifyMalware(apkfile):
    bRes = False
    for family in android_family:
        if family=="BladeHawk":
            analysis = BladeHawk()
            _log("[+] Verifying if it's BladeHawk.")
            bRes = analysis.verifyBladeHawk(apkfile)
            if bRes==True:
                break
        elif family=="AndroRat":
            analysis = AndroRat()
            _log("[+] Verifying if it's AndroRat.")
            bRes = analysis.verifyAndroRat(apkfile)
            if bRes==True:
                break
        elif family=="AhMyth":
            analysis = AhMyth()
            _log("[+] Verifying if it's AhMyth.")
            bRes = analysis.verifyAhMyth(apkfile)
            if bRes==True:
                break
        elif family=="apt-c-23":
            analysis = APT_C_23()
            _log("[+] Verifying if it's APT-C-23.")
            bRes = analysis.verifyAPT_C_23(apkfile)
            if bRes==True:
                break
        elif family=="apt-c-27":
            analysis = APT_C_27()
            _log("[+] Verifying if it's APT-C-27.")
            bRes = analysis.verifyAPT_C_27(apkfile)
            if bRes==True:
                break
        elif family=="BankBot":
            analysis = BankBot()
            _log("[+] Verifying if it's BankBot.")
            bRes = analysis.verifyBankBot(apkfile)
            if bRes==True:
                break
        elif family=="CapraRAT":
            analysis = CapraRAT()
            _log("[+] Verifying if it's CapraRAT.")
            bRes = analysis.verifyCapraRAT(apkfile)
            if bRes==True:
                break
        elif family=="ChinaSMSStealer":
            analysis = ChinaSMSStealer()
            _log("[+] Verifying if it's ChinaSMSStealer.")
            bRes = analysis.verifyChinaSMSStealer(apkfile)
            if bRes==True:
                break
        elif family=="Dendroid":
            analysis = Dendroid()
            _log("[+] Verifying if it's Dendroid.")
            bRes = analysis.verifyDendroid(apkfile)
            if bRes==True:
                break
        elif family=="EventBot":
            analysis = EventBot()
            _log("[+] Verifying if it's EventBot.")
            bRes = analysis.verifyEventBot(apkfile)
            if bRes==True:
                break
        elif family=="FakeSpy":
            analysis = FakeSpy()
            _log("[+] Verifying if it's FakeSpy.")
            bRes = analysis.verifyFakeSpy(apkfile)
            if bRes==True:
                break
        elif family=="FlexBotnet":
            analysis = FlexBotnet()
            _log("[+] Verifying if it's FlexBotnet.")
            bRes = analysis.verifyFlexBotnet(apkfile)
            if bRes==True:
                break
        elif family=="moqhao":
            analysis = moqhao()
            _log("[+] Verifying if it's Moqhao.")
            bRes = analysis.verifyMoqhao(apkfile)
            if bRes==True:
                break
        elif family=="MuddyWater":
            analysis = MuddyWater()
            _log("[+] Verifying if it's MuddyWater.")
            bRes = analysis.verifyMuddyWater(apkfile)
            if bRes==True:
                break
        elif family=="Saefko":
            analysis = Saefko()
            _log("[+] Verifying if it's Saefko.")
            bRes = analysis.verifySaefko(apkfile)
            if bRes==True:
                break
        elif family=="SandroRat":
            analysis = SandroRat()
            _log("[+] Verifying if it's SandroRat.")
            bRes = analysis.verifySandroRat(apkfile)
            if bRes==True:
                break
        elif family=="spynote":
            analysis = spynote()
            _log("[+] Verifying if it's SpyNote.")
            bRes = analysis.verifySpyNote(apkfile)
            if bRes==True:
                break
        elif family=="SyrianMT":
            analysis = SyrianMT()
            _log("[+] Verifying if it's SyrianMT.")
            bRes = analysis.verifySyrianMT(apkfile)
            if bRes==True:
                break
        elif family=="TeleRat":
            analysis = TeleRat()
            _log("[+] Verifying if it's TeleRat.")
            bRes = analysis.verifyTeleRat(apkfile)
            if bRes==True:
                break
        elif family=="Triout":
            analysis = Triout()
            _log("[+] Verifying if it's Triout.")
            bRes = analysis.verifyTriout(apkfile)
            if bRes==True:
                break
        elif family=="Vamp":
            analysis = Vamp()
            _log("[+] Verifying if it's Vamp.")
            bRes = analysis.verifyVamp(apkfile)
            if bRes==True:
                break
        elif family=="WhiteBroad":
            analysis = WhiteBroad()
            _log("[+] Verifying if it's WhiteBroad.")
            bRes = analysis.verifyWhiteBroad(apkfile)
            if bRes==True:
                break
        elif family=="Xenomorph":
            analysis = Xenomorph()
            _log("[+] Verifying if it's Xenomorph.")
            bRes = analysis.verifyXenomorph(apkfile)
            if bRes==True:
                break
        

#-------------------------------------------------------------
# logo : Ascii Logos like the 90s. :P
#-------------------------------------------------------------
def logo():
    print('\n')
    print(' ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __   ')
    print('/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \  ')
    print('\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \ ')
    print(' \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\\\"\_\\')
    print('  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/')
    print('\n')
    print(" Extract intel from this Android mallie!")
    print(" Jacob Soo")
    print(" Copyright (c) 2018-2022\n")
                                                                                                                      

if __name__ == "__main__":
    description='C&C Extraction tool for Android Malware'
    parser = argparse.ArgumentParser(description=description,
                                     epilog='--file and --directory are mutually exclusive')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f','--file',action='store',nargs=1,dest='szFilename',help='filename',metavar="filename")
    group.add_argument('-d','--directory',action='store',nargs=1,dest='szDirectory',help='Location of directory.',metavar='directory')

    args = parser.parse_args()
    Filename = args.szFilename
    Directory = args.szDirectory
    is_file = False
    is_dir = False
    try:
        is_file = os.path.isfile(Filename[0])
    except:
        pass
    try:
        is_dir = os.path.isdir(Directory[0])
    except:
        pass
    logo()
    if Filename is not None and is_file:
        if check_apk_file(Filename[0])==True:
            verifyMalware(Filename[0])
        else:
            print("This is not a valid apk file : %s" % Filename[0])
    if Directory is not None and is_dir:
        for root, directories, filenames in os.walk(Directory[0]):
            for filename in filenames: 
                szFile = os.path.join(root,filename) 
                if check_apk_file(szFile)==True:
                    verifyMalware(szFile)
                else:
                    print("This is not a valid apk file : %s" % szFile)