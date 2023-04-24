#!env python
"""
    The program VFuzz-Public is a fuzzer targeting Z-WaVe Protocol that helps find devices vulnerabilities.

    VFuzz-Public has been REDUCED from the original one with the aim to reduce advanced functionalities that could be
    misused by bad actor to attack smart home devices.

    VFuzz-Public  is distributed in the hope that it will be useful to researchers, but WITHOUT ANY
    WARRANTY; hence, be responsible while using VFuzz-Public.

    We recommend testing ONLY your PERSONAL DEVICES in a CLOSED CONTROLLED environment to avoid jamming Z-Wave 908 - 916 MHz or ANY
    frequency that is used for different purpose per COUNTRY. It may be ILLEGAL to send packets in reserved frequencies
    without a prior AUTHORIZATION. Please consult with your institution for using open frequencies.

"""

__author__ = "Carlos Nkuba"
__copyright__ = "https://ieeexplore.ieee.org/abstract/document/9663293/"
__credits__ = "https://ieeexplore.ieee.org/abstract/document/9663293/"
__license__ = "https://ieeexplore.ieee.org/abstract/document/9663293/"
__version__ = "Public v1.0.0"
__maintainer__ = "Carlos Nkuba"
__email__ = "use GitHub to provide an Issue"
__status__ = "VFuzz Public REDUCED VERSION Release"

import subprocess as sp
import fuzzer_config
import zwaveUtil
import random
import datetime
from datetime import datetime
from threading import RLock
import sys

try:
    from rflib import *
except ImportError:
    print "Error : Please Install rflib... Program Exiting...\n"
    sys.exit(0)

### Variable Declaration


# RF Dongle variables
global d1, d2, debug

# Fuzzer variables
global rxcount, txcount, ercount
rxcount = 0
txcount = 0
ercount = 0
debug = 0
global i
global pkt

global nodeid_VFUZZ
global numberOfRun, timeout
global ack_Dev
global timeoutFuzzer
global start_time_all
start_time_all = time.time()

timeoutFuzzer = fuzzer_config.timeoutFuzzer

# Z-Wave frame bytes
global d_init
global d_header
global homeID, nodeID
global d_homeID, d_nodeID
global nop, nop_ctrl
global _verbose_vfuzz
_verbose_vfuzz = fuzzer_config.verbose_vfuzz
# Header (Preambule + Start of Frame Delimiter)
d_init = "\x00\x0E"
d_header = "\x41\x01"
pkt = None
i = 0

global log_file_name
log_file_name = "./logs/log_fuzzTesting.wfl"

""" TESTing DEVICE Availability"""
global is_crash, deviceAck, frames, thread, threadX

""" TestAndCheck"""
global timeout
global deviceState
global deviceAck
global frames
global debug2
global fileout

is_crash = True  ### to modify
timeout = 3  ##  Test for 5 seconds
device_State = True
deviceAck = None
frames = None
fileout = 1
debug2 = 0

is_crash = None
thread = None
threadX = None
testcase = None
result_available = threading.Event()
lock = RLock()

## Output variables
global clearScreen
clearScreen = sp.call('clear', shell=True)
tool_version = "1.0.0"

## Logging information
year = datetime.today().year
month = datetime.today().month
day = datetime.today().day
hour = datetime.today().hour
minute = datetime.today().minute
second = datetime.today().second
microsecond = datetime.today().microsecond
starting_time = "{0}-{1}-{2} {3}:{4}:{5}.{6}".format(year, month, day, hour, minute, second, microsecond)


def load_file(fname):
    with open(fname, "rb") as f:
        return bytearray(f.read())


def save_file(fname, data):
    with open(fname, "wb") as f:
        f.write(str(data))


def save_file_all(fname, data):
    with open(fname, "a") as f:
        f.write(str(data))


def checksum(data):
    b = 255
    for i in range(2, len(data)):
        b ^= int(data[i].encode("hex"), 16)
    return format(b, '02x').decode("hex")


def post_build_pkt(d_SrcNode, d_nodeID, d_payload):
    global d_init
    global d_header
    global d_homeID

    ## Generate length
    d_lenght = len(d_payload) + len(hex(d_homeID)) + len(d_header) + 4  # 4=srcid+ 2bytes init + len
    d_lenght = format(d_lenght, '02x')
    d_lenght = d_lenght.decode("hex")
    ## Generate Checksum
    d_checksum = checksum(
        d_init + format(d_homeID, '02x').decode("hex") + d_SrcNode + d_header + d_lenght + d_nodeID + d_payload)
    pktToSend = format(d_homeID, '02x').decode(
        "hex") + d_SrcNode + d_header + d_lenght + d_nodeID + d_payload + d_checksum
    return pktToSend


def generatePacket(homeid, src, dst, pld):
    global debug
    global d_init, d_header
    global d_homeID
    ## Encording
    _homeid = format(homeid, '02x').decode("hex")
    _src = format(src, '02x').decode("hex")
    _dst = format(dst, '02x').decode("hex")
    _pld = pld
    ## Generate length
    d_lenght = len(_pld) + len(_homeid) + len(d_header) + 4  # 4=srcid+ 2bytes init + len
    d_lenght = format(d_lenght, '02x')
    d_lenght = d_lenght.decode("hex")

    ## Generate Checksum
    d_checksum = checksum(d_init + _homeid + _src + d_header + d_lenght + _dst + _pld)

    # construct frame
    pkt = _homeid + _src + d_header + d_lenght + _dst + _pld + d_checksum
    # print "NOP Data to send :", pkt.encode("hex")

    if debug == 1:
        print "Data to send :", pkt.encode("hex")
    return pkt


def send_vfuzz(pkt):
    global d_init, d_header
    try:
        # for _ in range(3):
        for _ in range(2):
            # d1.setModeTX()  # enter the correct mode first
            d1.RFxmit(invert(pkt))
            time.sleep(0.025)
            d1.setModeIDLE()  # DO THIS TO AVOID TIMEOUTS!
            time.sleep(0.025)
        return

    except KeyboardInterrupt:
        d1.setModeIDLE()
        return
        # return
    except ChipconUsbTimeoutException:
        pass
    except Exception, e:
        d1.setModeIDLE()
        sys.exit("Error %s" % str(e))
        return


def invert(data):
    datapost = ''
    for i in range(len(data)):
        datapost += chr(ord(data[i]) ^ 0xFF)
    return datapost


def calculateChecksum(data):
    checksum = 0xff
    for i in range(len(data)):
        checksum ^= ord(data[i])
    return checksum


def testAndCheck():  ### Monitor for one dongle
    global is_crash
    global fuzztesting
    # global is_crash2
    global homeID, nodeID
    global d_homeID, d_nodeID
    global debug

    global fileout
    global nop
    global deviceAck
    global frames
    global txcount
    global log_file_received
    global result_available
    global thread
    global ercount

    # YardStick Dongles
    global d1, d2

    global timeout
    global deviceState
    global deviceAck
    global frames
    global debug2
    global fileout

    is_crash = True  ### to modify
    device_State = True
    deviceAck = None
    frames = None
    # fileout = 1
    # debug2 = 0

    # debug = 0
    # debug2 = 0
    # fileout = 0
    # fuzztesting = True

    # nop = generatePacket(d_homeID, 0x01, d_nodeID, '\x00')
    # d_header = "\x41\x01"
    # timeout = 5  ##  Test for 3 seconds

    if debug: print "Monitoring device State"

    """ Set the device in Idle mode"""

    t1 = time.time()
    timeout = 5  ##  Test for 5 seconds
    time.sleep(0.025)

    """ Do not use d1.setModeTX()  because it will send random packet and 
            flag a CRC ERROR in Sniffer programe """
    # d1.setModeTX()  # DO NOT USE THIS IT WILL FLAG AN CRC ERROR in sniffer programme
    ## due to random packet that it is transmitting
    ##

    # d1.RFxmit(invert(nop))

    d1.setModeIDLE()  # WITHOUT THIS YOU WILL GET USB TIMEOUTS!

    while time.time() - t1 < timeout:
        # while True:
        d1.setModeIDLE()
        time.sleep(0.050)

        try:
            global frame_nb
            payload = ""
            # deviceAck = None
            # fileout = 1
            d1.RFxmit(invert(nop))
            d1.setModeRX()
            deviceAck = d1.RFrecv(10)[0]
            # print("\nBrut ACK: " + deviceAck)
            # print("\nBrut Converted into hex: " + deviceAck.encode("hex"))

            d1.setModeIDLE()
            deviceAck = invert(deviceAck)
            # print("\nAfter inversion: " + deviceAck)
            # print("\n After inversion Converted into hex: " + deviceAck.encode("hex"))
            # ## Selecting only first 10 bytes
            # deviceAck = deviceAck[0:10]
            # print("\n 10 First Bytes: " + deviceAck.encode("hex"))


            """Testing device Status"""
            # send_corefuzzRaw(nop)

            if deviceAck:
                deviceAck = deviceAck[0:10]
                if debug: print deviceAck.encode("hex")
                deviceAck = deviceAck.encode("hex")
                # Decode Zwave frame
                HomeID = deviceAck[0:8]
                SrcNode = deviceAck[8:10]
                FrameControl1 = deviceAck[10:12]  ### ACK Header is 0x03
                FrameControl1 = deviceAck[12:14]
                Length = deviceAck[14:16]
                DstNode = deviceAck[16:18]
                # payload = res[18:]  ### ACK Frame do not have payload
                crc = deviceAck[18:20]
                if Length == "0a" and SrcNode == format(d_nodeID, '02x'):  # ACK frame
                    if debug: print "	ACK response from " + SrcNode + " to " + DstNode

                    if debug2: print " \n	ACK response from " + SrcNode + " to " + DstNode
                    if fileout:
                        logAckFile = open("logs/Ack_received.txt", "w")
                        logAckFile.write("Log of Last received ACK from Target device while sending Z-Wave NOP frame\n")
                        logAckFile.write("Raw ACK Value: " + deviceAck)
                        logAckFile.write("\nACK_No: " + str(
                            txcount) + "  |  " + "Timestp: " + datetime.now().strftime(
                            '%Y-%m-%d %H:%M:%S') + "  |  " + "HomeID: " + HomeID + "  |  " + "Src: " + SrcNode + "  |  " + "Dst: " + DstNode + "  |  " + "CRC: " + crc)
                        logAckFile.write(
                            "\n-----------------------------------------------------------------------------------------------------------------------------------------------------")
                        logAckFile.close()

                    is_crash = False
                    device_State = False
                    # return device_State
                    d1.setModeIDLE()
                    break
                elif deviceAck == None:
                    logInterestingTestcase = open("logs/interestingTestCase.txt", "w")
                    logInterestingTestcase.write("Interesting test cases: \n")
                    logInterestingTestcase.write("Raw sent packet: " + str(pkt))  ## Log interesting packet to file
                    logInterestingTestcase.close()
                    break
                # else:
                #     break

        except ChipconUsbTimeoutException:
            pass
        except KeyboardInterrupt:
            d1.setModeIDLE()
            device_State = 100
            return device_State
            # break
            # return

        except Exception, e:  ## catch error
            d1.setModeIDLE()  ### Avoid USB TIMEOUT
            sys.exit("Error %s" % str(e))
    # d1.setModeIDLE()  ###Avoid USB TIMEOUT
    d1.setModeIDLE()  ## to check
    return device_State


class Printer():
    """Print things to stdout on one line dynamically"""

    def __init__(self, data):
        sys.stdout.write("\r\x1b[K" + data.__str__())
        sys.stdout.flush()


def save_log_funtion_received(txcount, pkt, testcase, is_crash):
    global log_file_name
    global log_file_received
    log_file = open(log_file_received, "a")
    log_file.write("\t\t{")
    log_file.write("\"Pkt_no\" : {0},".format(txcount))
    log_file.write("\"Bug\" : \"y\",")
    # log_file.write("}")
    log_file.write("},\n")
    log_file.close()


def save_log_funtion(txcount, pkt, testcase, is_crash):
    global log_file_name
    log_file = open(log_file_name, "a")
    log_file.write("\t\t{")
    log_file.write("\"no\" : {0},".format(txcount))
    log_file.write("Timestp: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ",")
    if is_crash:
        log_file.write("\"crash\" : \"y\",")
        log_file.write("\"Payload\" : {")
        log_file.write(pkt)
        log_file.write("}")
        log_file.write("},\n")

        log_file.close()
    else:
        log_file.write("\"crash\" : \"n\",")
        log_file.write("\"Payload\" : {")
        log_file.write(pkt)
        log_file.write("}")
        log_file.write("},\n")
        log_file.close()


def console_output_function(i, testcase, pkt, verbose_vfuzz):
    Elapsed_time = time.time() - start_time_all
    if verbose_vfuzz == False:
        toPrint = "     [*] Pkt# : " + str(i) + ". Elaps: %.2f" % Elapsed_time + " sec." + " Test case: " + str(
            testcase) + " "  # + str(hexdump(pkt))
        Printer(toPrint)
        """ Scapy Packet visualization from: https://scapy.readthedocs.io/en/latest/usage.html """
    else:
        toPrint = "      [*] Pkt#:" + str(i) + " " + pkt
        Printer(toPrint)


def cleanupDongle(d):
    global d1, d2
    time.sleep(.125)
    if d == None:
        pass
    else:
        # Resetting the First Dongle
        d.setModeIDLE()  ## Create Error

    return


def fuzzing_summary():
    global log_file_name
    global ercount
    Elapsed_time = time.time() - start_time_all

    log_stat = open(log_file_name, "a")
    log_stat.seek(-2, os.SEEK_END)
    log_stat.truncate()
    log_stat.write('\n\t]\n')
    log_stat.write('}')
    log_stat.close()

    log_stat = open(log_file_name, "r")
    contents = log_stat.readlines()
    log_stat.close()
    contents.insert(7, '\t"count" : {\n\t\t"all" : %d,\n\t\t"errors, hangs " : %d,\n\t\t"passed" : %d\n\t},\n' % (
        int(txcount), int(ercount), int(txcount) - int(ercount)))

    log_stat = open(log_file_name, "w")
    contents = "".join(contents)
    log_stat.write(contents)
    log_stat.close()

    print
    print"-----------------------------[SUMMARY]---------------------------------"
    print"Start time    : " + str(starting_time)
    print"End time      : " + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print"Runtime       : {0} seconds.".format(round(Elapsed_time, 2))
    print
    print"          [+][+][+] Total packets sent                    : {0}".format(txcount)
    print"          [+][+][+] Total hang(s), error(s)               : {0}  ".format(ercount)
    print "----------------------------------------------------------------------"


def mutate(homeid, nodeid, verb, dongle1, dongle2):
    global d1, d2
    global homeID, NodeID
    global d_homeID, d_nodeID
    d_homeID = homeid
    d_nodeID = nodeid
    d1 = dongle1
    d2 = dongle2

    global year, month, day, hour, minute, second, microsecond, starting_time
    global start_time_all
    global Elapsed_time
    global runtime
    global log_file_sent
    global log_file_received
    global log_file_error
    global log_file_response
    global timeoutFuzzer
    global log_file_name
    global nop
    global thread

    global _verbose_vfuzz
    """Check for Log File"""
    if not os.path.exists("./logs"):
        os.makedirs("./logs")

    global pkt
    global i
    pkt = None
    global txcount, rxcount, ercount, error
    txcount = 0
    rxcount = 0
    ercount = 0
    error = 0

    global is_crash
    global testcase

    clearScreen

    """logging information for crash"""

    log_file_name = "./logs/log_fuzzTesting.wfl".format(year, month, day, hour, minute,
                                                        second,
                                                        microsecond)
    log_file = open(log_file_name, "w")
    save_file_all(log_file_name, "{\n")
    save_file_all(log_file_name, "\t\"ToolVer\" : \"{0}\",\n".format(tool_version))
    save_file_all(log_file_name, "\t\"Interface\" : \"Z-Wave\",\n")
    save_file_all(log_file_name, "\t\"HomeId\" : \"{0}\",\n".format(hex(d_homeID)))
    save_file_all(log_file_name, "\t\"NodeId\" : \"{0}\",\n".format(hex(d_nodeID)))
    save_file_all(log_file_name,
                  "\t\"Starting_time\" : \"{0}-{1}-{2} {3}:{4}:{5}.{6}\",\n".format(year, month, day, hour, minute,
                                                                                    second, microsecond))
    save_file_all(log_file_name, "\t\"Protocol\" : \"Z-Wave\",\n")
    save_file_all(log_file_name, "\t\"packet\" : [\n")
    log_file.close()

    log_file_received = "./logs/log_received_{0}_{1}_{2}_{3}-{4}-{5}-{6}.wfl".format(year, month, day, hour, minute,
                                                                                     second, microsecond)

    nop = generatePacket(d_homeID, 0x01, d_nodeID, '\x00')
    # print nop
    # print "NOP Data to send :", nop.encode("hex")

    """ FUZZING LOOP STARTS with Mutation """

    t1 = time.time()
    print
    print "[*] Phase 2 : Fuzz Testing "

    try:
        testModetime = fuzzer_config.timeout_field_Mut
        t1 = time.time()
        deviceState = False

        """ TESTING """

        is_crash = False

        testcase = "ZW_T0_AllRnd"
        t1 = time.time()
        ### Instanciate a Z-Wave Packet with Valid HomeID and NodeID
        pkt = zwaveUtil.ZwavePacket()
        pkt.setHomeID(d_homeID)
        pkt.setDst(d_nodeID)

        test = None
        """DEVICE INITIAL TESTING PHASE """
        test = testAndCheck()  ## Use this if testing with ONLY one Yardstick one
        if test is True:
            print ("\n[!] Device Unavailable !!")
            return

        else:
            print ("\n    [*][*] Testcase: " + testcase)

            while test is not True and time.time() - t1 < testModetime and time.time() - start_time_all < timeoutFuzzer:
            # while True:
                i += 1
                txcount = i

                ### Testcase ZW_T1 Mutates All field for VFuzz-Public version
                # pkt.setSrc(random.randint(0, 255))

                # pkt.setFrameControl_1(0x41)  ### get ACK from target device
                pkt.setFrameControl_1(0x11)  ## 0x11  NO ACK || 0x31 for NO ACK ||  0x41 0x51 0x71 0x61

                pkt.setFrameControl_2(0x01)
                pkt.setSrc(0xC8)  ### Equals 200  in decimal
                pkt.setCmdClass(random.randint(0, 255))
                pkt.setCmd(random.randint(0, 255))
                pkt.setValue(random.randint(0, 255))
                pkt.setValue1(random.randint(0, 255))
                pkt.setValue2(random.randint(0, 255))
                pkt.setValue3(random.randint(0, 255))
                pkt.setValue4(random.randint(0, 255))
                pkt.setValue5(random.randint(0, 255))
                pkt.setValue6(random.randint(0, 255))
                pkt.setValue7(random.randint(0, 255))
                pkt.setValue8(random.randint(0, 255))

                """Device Testing"""
                test = None
                # time.sleep(0.025)## remove
                """DEVICE SECOND TESTING  """
                test = testAndCheck()  ## For one dongle
                # time.sleep(0.025)
                if test is False:
                    pkt_final = pkt.postbuild_Pkt()
                    time.sleep(0.25)
                    ### !!! Sometimes you will have CRC_ERROR due to radio noise
                    # ## Because you use one YST dongle to transmit and receive !!! just skip that
                    send_vfuzz(pkt_final)
                    # send_vfuzz(pkt.postbuild_Pkt())
                    console_output_function(txcount, testcase, str(pkt), _verbose_vfuzz)
                    save_log_funtion(txcount, str(pkt), testcase, is_crash)
                    time.sleep(0.25)
                    d1.setModeIDLE()
                    test = None
                    # time.sleep(0.025)

                elif test is 100:
                    print
                    print("User Interruption (Ctrl +C)! Exiting ...")
                    break
                else:
                    ercount = ercount + 1

                    save_log_funtion(txcount, str(pkt), testcase, is_crash)
                    print
                    print("\n[!] Target Device ID: " + str(hex(d_nodeID)) + " is NOT available")
                    break

            print("\n Done ")
            fuzzing_summary()

        return

    except ChipconUsbTimeoutException:
        pass
    except KeyboardInterrupt:
        d1.setModeTX()
        d1.setModeIDLE()
        print
        print("[!] Exiting...")
        print("[!] Please Reset RF Dongle !")
        return

    except Exception as e:
        d1.setModeIDLE()
        print ("Error Found !")
        print(e)
        sys.exit(1)  ## exit(1) means there was some issue/error/problem
