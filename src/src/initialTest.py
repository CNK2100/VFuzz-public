# coding=utf-8
#!env python
"""
    The program VFuzz-Public is a Z-WaVe Protocol Fuzzer that helps reveal
    Z-wave devices vulnerabilities

    VFuzz-Public has been REDUCTED from the original one with the aim to reduce advanced functionalities that could be
    misused by bad actor to attack smart home devices.

    VFuzz-Public  is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; hence, be responsible while using VFuzz-Public.

    We advice to test ONLY your PERSONAL DEVICES in a CLOSED CONTROLLED environment to avoid jamming 916 MHz
    signal that is used for different purpose per COUNTRIES and it is ILLEGAL to send packets in that frequency
    witout a prior AUTHORIZATION.

"""

__author__ = "Carlos Nkuba"
__copyright__ = "Copyright 2021, CCSLab Korea University"
__credits__ = "https://ieeexplore.ieee.org/abstract/document/9663293/"
__license__ = "https://ieeexplore.ieee.org/abstract/document/9663293/"
__version__ = "Public v1.0.1"
__maintainer__ = "Carlos Nkuba"
__email__ = "use GitHub to provide an Issue"
__status__ = "VFuzz Public Reducted Release"


# from vfuzz import cleanupDongle

try:
    from rflib import *
except ImportError:
    print "Error : Please Install rflib... Program Exiting...\n"



### ADDED Import
import time
import subprocess as sp
from subprocess import call
import random
import signal
import datetime
from datetime import datetime
import os
import serial
import binascii
import string
import sys
import bitstring



# # RF Dongle variables
global d1, d2



def initialTestingPhase(homeid1, nodeid1, verb, dongle1, dongle2):
    """ Initial device Test  Reducted from original VFuzz. !!"""
    print("[*] Phase 1 : Initial Device Testing .... SKIPPED!!!!")
    print
    time.sleep(0.025)
    print("     [*][*][*] STEP 1: Data Authenticity Check .. SKIPPED!!!!")
    time.sleep(0.025)
    print("     [*][*][*] STEP 2: Information Disclosure Check .. SKIPPED!!!!")
    time.sleep(0.025)
    print("     [*][*][*] STEP 3: Specification Violation check.. SKIPPED!!!!")
    time.sleep(0.025)
    print("     [*][*][*] STEP 4: Device NIF Info gathering check... SKIPPED!!!!")
    time.sleep(0.025)
    print("     [*][*][*] STEP 5: Device Remote Code Execution check... SKIPPED!!!!")




if __name__ == "__main__":
    initialTestingPhase()
