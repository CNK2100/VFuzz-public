# VFuzz-Public-Dev
This is the simplified and reduced version of VFuzz. It aims to provide to
researchers core information about fuzzing Z-Wave devices.

VFuzz-Public  is distributed in the hope that it will be useful to researchers, 
but WITHOUT ANY WARRANTY; hence, be responsible while using VFuzz-Public.

We recommend testing ONLY your PERSONAL DEVICES in a CLOSED CONTROLLED environment to avoid jamming 908 MHz or ANY
frequency that is used for different purpose per COUNTRY. It may be ILLEGAL to send packets in reserved frequencies
without a prior AUTHORIZATION.

Fuzzing throughput has been reduced as the version runs on ONE YardStick One 
dongle.
Mutation operators have been reduced to Random ONLY.



Requirements:

sudo apt-get update
sudo apt-get upgrade
sudo apt-get install python  ## For Pyton 2

##Install RFCAT
## https://github.com/atlas0fd00m/rfcat

sudo apt-get install libusb-1.0-0-dev
sudo apt-get install python-pip
sudo apt install python-usb libusb-1.0.0 make
sudo apt-get install libusb-1.0-0-dev

sudo apt install python-pydot python-pydot-ng graphviz
sudo apt-get install ipython
sudo apt-get install git
sudo pip install PySide2
sudo apt-get install python-numpy
pip install numpy
pip install bitstring
pip install psutil
pip install requests
sudo apt install sdcc


Run VFuzz:

sudo python ./vufzz.py

STOP VFUZZ: CTRL + Z





