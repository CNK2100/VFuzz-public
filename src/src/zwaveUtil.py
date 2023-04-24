import time


class ZwavePacket:  # Z-Wave basic packet
    global homeID
    global nodeID
    d_init = "\x00\x0E"
    d_header = "\x41\x01"

    def __init__(self):
        # self.header=None
        self.homeID = 0xa1a2a3a4
        self.src = 0x01
        self.frameControl_1 = 0x41
        self.frameControl_2 = 0x01
        self.length = 0x0C
        self.dst = 0xff
        self.cmdClass = 0x25  # COMMAND_CLASS_SWITCH_BINARY: 0x25
        self.cmd = 0x01  # COMMAND : SWITCH_BINARY_SET: 0x01
        self.value = 0xff  # Switch Value: FF == ON  and value : OO == OFF
        self.value1 = 0x00
        self.value2 = 0x00
        self.value3 = 0x00
        self.value4 = 0x00
        self.value5 = 0x00
        self.value6 = 0x00
        self.value7 = 0x00
        self.value8 = 0x00

        self.crc = 0x15

    def validPacket(self):
        self.crc != 0

    def getHeader(self):
        return self.header

    def setHeader(self, header):
        self.header = header

    def getHomeID(self):
        # x = int(self.homeId)
        return self.homeID

    def setHomeID(self, homeId):
        self.homeID = homeId

    def getSrc(self):
        # x = int(self.sourceId)
        # return x
        return self.src

    def setSrc(self, sourceId):
        # self.sourceId = sourceId
        self.src = sourceId

    def getFrameControl_1(self):
        return self.frameControl_1

    def setFrameControl_1(self, frameControl_1):
        self.frameControl_1 = frameControl_1

    def getFrameControl_2(self):
        return self.frameControl_2

    def setFrameControl_2(self, frameControl_2):
        self.frameControl_2 = frameControl_2

    def getLength(self):
        return self.length

    def setLength(self, length):
        self.length = length

    def getDst(self):
        return self.dst

    def setDst(self, destId):
        self.dst = destId

    def getCmdClass(self):
        return self.cmdClass

    def setCmdClass(self, cmdClass):
        self.cmdClass = cmdClass

    def getCmd(self):
        return self.cmd

    def setCmd(self, cmd):
        self.cmd = cmd

    def getValue(self):
        return self.value

    def setValue(self, value):
        self.value = value

    def getValue1(self):
        return self.value1

    def setValue1(self, value1):
        self.value1 = value1

    def getValue2(self):
        return self.value2

    def setValue2(self, value2):
        self.value2 = value2

    def getValue3(self):
        return self.value3

    def setValue3(self, value3):
        self.value3 = value3

    def getValue4(self):
        return self.value4

    def setValue4(self, value4):
        self.value = value4

    def getValue5(self):
        return self.value5

    def setValue5(self, value5):
        self.value5 = value5

    def getValue6(self):
        return self.value6

    def setValue6(self, value6):
        self.value6 = value6

    def getValue7(self):
        return self.value7

    def setValue7(self, value7):
        self.value7 = value7

    def getValue8(self):
        return self.value8

    def setValue8(self, value8):
        self.value8 = value8

    def getCrc(self):
        return self.crc

    def setCrc(self, crc):
        self.crc = crc

    def __str__(self):
        """
        Human readable string representation of the Z-Wave packet
        :return: srt
        """
        try:
            #
            # return "Net:%s Src:%s FC:%s FC2:%s Len:%s Dst:%s CmdCl:%s Cmd:%s Pld:%s%s%s%s%s%s%s%s%s Crc:%s" % \
            return "N:%s S:%s FC:%s%s L:%s D:%s Pld:%s%s%s%s%s%s%s%s%s%s%s C:%s" % \
                (hex(self.homeID), hex(self.src), hex(self.frameControl_1), hex(self.frameControl_2), \
                 hex(self.length), hex(self.dst), hex(self.cmdClass), hex(self.cmd), hex(self.value), \
                 hex(self.value1), hex(self.value2), hex(self.value3), hex(self.value4), hex(self.value5), \
                 hex(self.value6), hex(self.value7), hex(self.value8), hex(self.crc))
        except KeyboardInterrupt:
            exit(0)
        except UnicodeDecodeError:
            return u'Home ID: %s Source ID: %s FC1: %s FC2: %s Length: %s Dst: %s CmdCl: %s Cmd: %s Val: %s Crc: %s' % \
                (format(self.homeID, '02x').decode("hex"), format(self.src, '02x').decode("hex"), \
                 format(self.frameControl_1, '02x').decode("hex"), format(self.frameControl_2, '02x').decode("hex"), \
                 format(self.length, '02x').decode("hex"), format(self.dst, '02x').decode("hex"), \
                 format(self.cmdClass, '02x').decode("hex"), format(self.cmd, '02x').decode("hex"), format(
                    self.value, '02x').decode("hex"), format(self.crc, '02x').decode("hex"))

    def pktTostr(self):
        """
        The string Hex representation of the Z-Wave packet
        :return: srt
        """
        try:
            return format(self.homeID, '02x').decode("hex") + format(self.src, '02x').decode("hex") + \
                format(self.frameControl_1, '02x').decode("hex") + format(self.frameControl_2, '02x').decode("hex") + \
                format(self.length, '02x').decode("hex") + format(self.dst, '02x').decode("hex") + \
                format(self.cmdClass, '02x').decode("hex") + format(self.cmd, '02x').decode("hex") + \
                format(self.value, '02x').decode("hex") + format(self.value1, '02x').decode("hex") + \
                format(self.value2, '02x').decode("hex") + format(self.value3, '02x').decode("hex") + \
                format(self.value4, '02x').decode("hex") + format(self.value5, '02x').decode("hex") + \
                format(self.value6, '02x').decode("hex") + format(self.value7, '02x').decode("hex") + \
                format(self.value8, '02x').decode("hex") + format(self.crc, '02x').decode("hex")

        except KeyboardInterrupt:
            exit(0)

    ### Checksum Generation for Hex data
    def calculateChecksum(self, data):
        checksum = 0xff
        for i in range(len(data)):
            checksum ^= ord(data[i])
        return checksum

    ## Checksum generation for String data
    def checksum_2(self, data):
        b = 255
        for i in range(2, len(data)):
            b ^= int(data[i].encode("hex"), 16)
        print "	-> Checksum :", format(b, '02x')
        return format(b, '02x').decode("hex")

    def postbuild_Pkt(self):
        # Header: PRE + SOF
        init = "\x00\x0E"
        header = "\x41\x01"

        ## Encording packet field to Hex string without 0x prefix
        _homeid = format(self.homeID, '02x').decode("hex")
        _src = format(self.src, '02x').decode("hex")
        _fc1 = format(self.frameControl_1, '02x').decode("hex")
        _fc2 = format(self.frameControl_2, "02x").decode("hex")
        _dst = format(self.dst, "02x").decode("hex")
        _cmdClass = format(self.cmdClass, "02x").decode("hex")
        _cmd = format(self.cmd, "02x").decode("hex")
        _val = format(self.value, "02x").decode("hex")
        _val1 = format(self.value1, "02x").decode("hex")
        _val2 = format(self.value2, "02x").decode("hex")
        _val3 = format(self.value3, "02x").decode("hex")
        _val4 = format(self.value4, "02x").decode("hex")
        _val5 = format(self.value5, "02x").decode("hex")
        _val6 = format(self.value6, "02x").decode("hex")
        _val7 = format(self.value7, "02x").decode("hex")
        _val8 = format(self.value8, "02x").decode("hex")

        ## Generate Valid Length
        ### _len value is integer
        _len = len(_homeid) + len(_src) + len(_fc1) + len(_fc2) + len(_dst) + len(_cmdClass) + len(_cmd) + len(_val) + \
               len(_val1) + len(_val2) + len(_val3) + len(_val4) + len(_val5) + len(_val6) + len(_val7) + \
               len(_val8) + 2  ### 2 = len(lenght field) + len( crc field)
        ### + 4 : + src(1) + len(1) + dst (1)  + checksum (1)

        # print
        # print(" Length is : " + str(_len) )
        self.setLength(_len)
        ### convert _len to Hexadecimal string  without 0x prefix
        _lenHex = format(_len, '02x').decode("hex")
        _lenght = _len
        #### Concatenate Z-Wave packet String Hex field
        # _init = format(init, "02x").encode("hex")
        _init = "\x00\x0E"
        pkt_Updated = _homeid + _src + _fc1 + _fc2 + _lenHex + _dst + _cmdClass + _cmd + _val + _val1 + \
                      _val2 + _val3 + _val4 + _val5 + _val6 + _val7 + _val8

        ### Generate Checksum
        _crc = self.calculateChecksum(pkt_Updated)

        ## Set CRC to Packet
        # print("Checksum is : " + str(_crc))
        self.setCrc(_crc)
        # pkt_Updated_full = _homeid+ _src + _fc1 + _fc2 + _lenHex + _dst + _cmdClass + _cmd + _val + _val1+\
        #      _val2 + _val3 + _val4 + _val5 + _val6 + _val7 + _val8 + format(self.crc, "02x").decode("hex")

        # print("The full packet is :" +self.pktTostr().encode("hex"))
        time.sleep(0.25)
        ### !!! Sometimes you will have CRC_ERROR due to radio noise  as you use one YST dongle !!! just skip that
        return self.pktTostr()  ### WORKING
