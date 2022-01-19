
"""
This is the configuration file for VFuzz.
"""

# Z-Wave home ID to fuzz in Hexadecimal in type String
homeid =0xF8A86B6B

# Z-Wave Target device node ID in hex
nodeid =0x02 ###"02" #"4E" #  0x4E

# Devices Z-Wave Frequency. uncomment your devices frequency and comment remaining
zwaveFrequency = 908420000  ### FOR USA
# zwaveFrequency = 868399841  ### For EU

# ## Verbose
verbose_vfuzz= False  # or True

# # Fuzzer global Timeout
timeoutFuzzer = 86400  ## 86400 seconds = 24 hours
#
# # field mutation timeout
timeout_field_Mut = 18000  ## 3600 in Seconds
#




