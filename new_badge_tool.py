# LqqkOut's code for badge transmissions
# Heavily modified by EvilMog
# Based on Data captured by AND!XOR and Illuminati party
# Also based on wireengineer screenshots

import serial
import time
import binascii

ser_device = '/dev/cu.usbserial-TG1101910'

ser = serial.Serial(ser_device, 4800, timeout=2)
ser.flushInput()
ser.flushOutput()

# give_points(): broadcast a badge ID, this is to simulate "meeting" other badges 
# around the con and was helpful for racking up points for the vending machine.
# only ~700 points could be gained by iterating through badge id's so there's
# some other secret sauce (status byte from doing the quests?) that would 
# hopefully convince the vending machine that you had a high enough balance
# to buy the black badge. 
def give_points(statusbyte, start, end, time_delay): 
    intro=bytearray.fromhex("536D6173683F"+statusbyte) # 01
    #for x in range (0,65536):
    #for x in range (0,67000):
    for x in range (start,end):
        mystring=hex(x)
        padded = str.format('{:06X}', int(mystring, 16))
        output = intro+bytearray.fromhex(padded)
        check_byte = 0xFF - (sum(output)-1)%256
        output.append(check_byte)
        print("X: ",x," Payload: ",output)
        ser.write(output)
        time.sleep(time_delay)

# Render bytes from the received serial data
def pretty_bytes(intro, data_raw, first_byte, last_byte):
    bytestring = (''.join(r' '+hex(letter)[2:] for letter in data_raw[first_byte : last_byte]))
    print(intro + ": " + bytestring)

#pretend to be a vending machine - send a code, badge dumps status back
def vendo(): 
    vendo=bytearray.fromhex("536D6173683F000102ffc3")
    ser.write(vendo)
    data_raw=ser.readline()
    data_array = data_raw.decode("all-escapes").split("\\x")

    print(data_array)


    # The previous line is just the beginning of a parser that I didn't
    # have time to complete. Best case is to find the intro string "Smash?" 
    # and start decoding with the bytes after that. pretty_bytes should take 
    # an offset and return a nicely-printed representation of those bits to 
    # match @wireengineer 's screenshots on twitter
    
#        print("Checksum:" + data_raw[0].decode("ascii"))
#        print("Checksum:" + data_raw[1])
#        print("Checksum:" + data_raw[2])
#        print("Checksum:" + data_raw[3])
#        print("Checksum:" + data_raw[4:6])

# loop to watch for badge transmissions, also used this to grab the
# vending machine handshake, other badge types, outhouses, and quest items
# it looks like everything looks like a badge to everything else. Clearly
# the vending machine "badge" has a special response, so other id's might
# as well ???
def read_badge():
    ser = serial.Serial(ser_device, 4800, timeout=2)
    ser.flushInput()
    ser.flushOutput()
    while (True):
        data_raw=ser.readline()
        # print(''.join(r' '+hex(letter)[2:] for letter in data_raw))
        print(data_raw.decode("all-escapes"))

def feed(): 
    feed_me=bytearray.fromhex("536D6173683F0300028937")
    ser.write(feed_me)

def pinkeye():
    pinkeye_cure=bytearray.fromhex("536D6173683F000002C102")
    ser.write(pinkeye_cure)

def outhouse():
    poop=bytearray.fromhex("536D6173683F000002A320")
    ser.write(poop)

#vendo()

def find_byte():
    data_string = bytearray.fromhex("536D6173683F000102FFC3536D6173683F0102020D0702DC013B02FF00024200240E002E71004F4D00309A000201BC016A000F0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBF080309C80E94").decode("all-escapes").split("\\x")
    print(data_string)
    counter = 0
    for line in data_string:
        if line == "3b":
            print(counter)
        counter = counter + 1

find_byte()

vendo()
