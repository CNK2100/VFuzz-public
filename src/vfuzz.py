# coding=utf-8
#!env python
"""
    The program VFuzz-Public is a fuzzer targeting Z-WaVe Protocol that helps find devices vulnerabilities.

    VFuzz-Public has been REDUCED from the original one with the aim to reduce advanced functionalities that could be
    misused by bad actor to attack smart home devices.

    VFuzz-Public  is distributed in the hope that it will be useful to researchers, but WITHOUT ANY
    WARRANTY; hence, be responsible while using VFuzz-Public.

    We recommend testing ONLY your PERSONAL DEVICES in a CLOSED CONTROLLED environment to avoid jamming 908 MHz or ANY
    frequency that is used for different purpose per COUNTRY. It may be ILLEGAL to send packets in reserved frequencies
    without a prior AUTHORIZATION.

"""

__author__ = "Carlos Nkuba"
__copyright__ = "https://ieeexplore.ieee.org/abstract/document/9663293/"
__credits__ = "https://ieeexplore.ieee.org/abstract/document/9663293/"
__license__ = "https://ieeexplore.ieee.org/abstract/document/9663293/"
__version__ = "Public v1.0.0"
__maintainer__ = "Carlos Nkuba"
__email__ = "use GitHub to provide an Issue"
__status__ = "VFuzz Public REDUCED VERSION Release"

import os

""" Libraries import"""

import atexit
import subprocess as sp
import time
import datetime
from datetime import datetime
import string
from sys import exit

"""" Import Extra"""
from src.vfuzz_fuzz import mutate, fuzzing_summary
from src.initialTest import initialTestingPhase
import fuzzer_config
# from rflib import *

try:
    from rflib import *

except ImportError:
    print ("Error : Please install rflib ....")
    print ("Program will Exit...\n")
    time.sleep(0.5)
    exit(1)

"""Variable declaration"""

## RF Dongles variables

global d1,d2 ## Yardstick dongles
global homeID, nodeID

d1= None
d2= None
fileout = 0
homeID = None ## Z-Wave Home ID init
nodeID = None ## Z-Wave Target Node ID init

## Fuzzer Timeout from ./fuzzer_config.py
timeoutFuzzer = fuzzer_config.timeoutFuzzer

## Clear Screen at start
clearScreen1 =sp.call('clear', shell=True)




def help():
    # clearScreen()
    print("VFuzz Public Version 1.0.0")
    print("Author : Carlos Nkuba CCS Lab  Korea University")
    print ("""
    The  VFuzz-Public program is a Z-WaVe Protocol Fuzzer that helps reveal Z-wave devices vulnerabilities.

    The VFuzz public version WILL provides source code for core Z-Wave fuzzing functionalities while REDUCING\
advanced features that could be misused by bad actors to attack smart home devices. For the same ethical\
considerations, we are not releasing the VFuzz PoC exploit code. 

    VFuzz-Public  is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; hence, be responsible\
    while using VFuzz-Public. 

    We advice to test ONLY your PERSONAL DEVICES in a CLOSED CONTROLLED  environment to avoid jamming the 916 MHz \
    signal that is used for different purpose per COUNTRIES and it is ILLEGAL to send packets in that frequency\
    without a prior AUTHORIZATION. Please consult with your institution for using open frequencies.

""")
    return


def handle_exit():
    global d1, d2
    try:
        print('\n[*] VFuzz normally stopped\n')
        return
    except Exception as e:
        print ("Error Found !")
        print(e)
        cleanupDongleFinal(d1)
        cleanupDongleFinal(d2)
        return

""" Handle  at Exit"""
atexit.register(handle_exit)


def clearScreen():
    # for mac and linux(here, os.name is 'posix')
    if os.name == 'posix':
        _ = os.system('clear')
    else:
        # for windows platfrom
        _ = os.system('cls')
    return

def cleanupDongleFinal(d):
    global d1, d2
    if d == None:
        pass
    else:
        # Resetting the First Dongle
        d.setModeIDLE()  ##
        d.cleanup()
        d.RESET()

    return



def cleanupDongle(d):
    global d1, d2
    time.sleep(.125)
    if d == None:
        pass
    else:

        # Resetting the Dongle
        d.setModeIDLE()
        # d.cleanup()
        # d.RESET()

    return



def radioDongleConfig(dongle1,dongle2):
    # RF Dongle variables Global Variables
    global d1, d2
    d1= dongle1
    d2 = dongle2
    zwaveFrequency= fuzzer_config.zwaveFrequency


    d1 = RfCat(0, debug=False)
    d2 = None



    try:
        """Configuring Dongle 1"""
        # Thanks to killerzee
        # d.setFreq(868399841) # EU
        # d.setFreq(916000000)  # US Frequency
        # d.setMdmModulation(MOD_GFSK)
        d1.setFreq(zwaveFrequency)  # US Frequency
        d1.setMdmModulation(MOD_2FSK)
        d1.setMdmSyncWord(0xaa0f)
        d1.setMdmDeviatn(20629.883)
        d1.setMdmChanSpc(199951.172)
        d1.setMdmChanBW(101562.5)
        d1.setMdmDRate(39970.4)
        d1.makePktFLEN(48)
        d1.setEnableMdmManchester(False)
        d1.setMdmSyncMode(SYNCM_CARRIER_15_of_16)
        d1.setModeIDLE()
        return

    except Exception, e:   # work on python 2.x
        print("Connect RF Dongles 1")
        print("Error: " + str(e))
        cleanupDongleFinal(d1)
        cleanupDongleFinal(d2)


    except KeyboardInterrupt:
        print ("\nUser Interruption !\nProgram will Exit...\n")
        cleanupDongleFinal(d1)
        cleanupDongleFinal(d2)
    return



def check_Hex_ValueHomeID(data):
    try:
        data = int_to_string_without_0x(data)

        if all(c in string.hexdigits for c in data) and len(data.decode("hex")) == 4:

            return
        else:
            print ("[!] " +str(data) +" is Not a valid Hexadecimal Z-Wave HomeID , please try again... \n")
            cleanupDongle(d1)
            # cleanupDongle(d2)
            sys.exit(1)

    except KeyboardInterrupt:
        cleanupDongle()
        sys.exit(1)
    except Exception as e:
        print (e)
        cleanupDongle(d1)
        # cleanupDongle(d2)
        print ("Error found! Exiting...")
        sys.exit(1)

    return


def check_Hex_ValueNodeID(data):

        try:

            data = int_to_string_without_0x(data)
            if all(d in string.hexdigits for d in data) and len(data.decode("hex")) == 1:
                return
            else:
                print("[!] " +str(data) +" is Not a valid Hexadecimal Z-Wave NodeID, please try again... \n")
                cleanupDongle(d1)
                # cleanupDongle(d2)
                sys.exit(1)
        except KeyboardInterrupt:
            print("\n[!]" +str(data) +" is User interruption! Exiting ... Please RESET Radio Dongle \n")
            cleanupDongle(d1)
            # cleanupDongle(d2)
            sys.exit(1)
        except Exception as e:
            print str(e)
            cleanupDongle(d1)
            # cleanupDongle(d2)
            print ("Error found! Exiting...")
            sys.exit(1)
        return


def int_to_string_without_0x(data):
    ## int to Hexadecimal with leading 0x
    data = hex(data)
    ## Removing leading 0x and convert to Hex
    data = data[2:]
    if len(data) ==1:
        data = "0"+ data
    return data


def hex_to_string(hex):
    if hex[:2] == '0x':
        hex = hex[2:]
    string_value = bytes.fromhex(hex).decode('utf-8')
    return string_value


def display():
    global homeID, nodeID
    clearScreen()

    print
    print("************************************************************************")
    print("***       Welcome to VFuzz-Public: A Z-Wave Protocol Fuzzer          ***")
    print("************************************************************************")
    print("""[!] Be Responsible while Fuzzing. Please test ONLY  your personal 
    devices in a controlled environment. Sending wireless packets to  
    unknown devices is ILLEGAL. This tool comes with  NO WARRANTY. """)
    print("")
    # print("                 [*]  Exit VFuzz  with Summary: CTRL + C ")
    print("                 [*]  Kill VFuzz process with : CTRL + Z ")
    print
    print("Start date & time     : " + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    print("Fuzzing timeout       : " + str((timeoutFuzzer / 60) / 60) + " Hours")
    print("Z-Wave HomeID         : " + str(hex(homeID)))
    print("Target NodeID         : " + str(hex(nodeID)))
    print("VFuzz-Public Ver      : 1.0.0")
    print("Test Suite            : ZWave Test Suite 1.0.0")
    print("Mutator               : FIPA")
    print(" ------------------------------[LOGS]----------------------------------")
    print

    return

def main():
    global d1, d2
    global homeID, nodeID
    # global clearScreen
    global args

    # if os.getuid() != 0:
    #     print
    #     print("Please run the program as Super-User \'sudo\' ")
    #     sys.exit(1)

    if not os.path.exists("./logs"):
        os.makedirs("./logs")

    argc = len(sys.argv)
    for i in range(argc):
        s = sys.argv[i]
        if i < argc:
            if s in ("-h"):
                clearScreen()
                print("")
                # print()
                help()
                exit(0)
            if s in ("-scan"):
                print("")
                clearScreen()
                scan.main()
                sys.exit(1)
            else:
                pass


    """Dongles Configuration"""
    radioDongleConfig(d1,d2)
    clearScreen()



    try:
        homeID = fuzzer_config.homeid
        check_Hex_ValueHomeID(homeID)

        nodeID = fuzzer_config.nodeid
        check_Hex_ValueNodeID(nodeID)

        """Display fuzzer summary"""
        display()

        initialTestingPhase(homeID, nodeID, False, d1, d2)
        # ### Call the fuzzing method
        mutate(homeID, nodeID, False, d1, d2)

    except KeyboardInterrupt:
        print("\n[!] User interruption! Exiting ... Please RESET Radio Dongle \n")
        cleanupDongle(d1)
        cleanupDongle(d2)

    cleanupDongle(d1)
    cleanupDongle(d2)
    return


if __name__ == "__main__":
    main()
