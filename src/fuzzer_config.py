
"""
This is the configuration file for VFuzz.
"""

# Z-Wave home ID to fuzz in Hexadecimal
# homeid =0xF8A86B6B
homeid =0xCB95A34A

# Z-Wave Target device node ID in Hexadecimal
nodeid =0x02 

# Z-Wave Frequency used. Select your devices frequency and comment remaining
zwaveFrequency = 908420000  ### FOR USA
# zwaveFrequency = 868399841  ### For EU

# ## Verbose
verbose_vfuzz= False  # or True

# # Fuzzer global Timeout
timeoutFuzzer = 86400  ## 86400 seconds = 24 hours
#
# # field mutation timeout
timeout_field_Mut = 18000  ## in seconds
