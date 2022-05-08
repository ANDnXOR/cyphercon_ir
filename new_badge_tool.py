# LqqkOut's code for badge transmissions
# carfucar checksum generator
# evilmog heavily modified and rewrote the vendo() and badge send
# MIT Licensed
# Leeky for the perl to python crypto() translation
#   has not been tested yet


import serial
import time
import binascii

ser_device = '/dev/cu.usbserial-TG1101910'

ser = serial.Serial(ser_device, 4800, timeout=2)
ser.flushInput()
ser.flushOutput()

# Render bytes from the received serial data
def pretty_bytes(intro, data_raw, first_byte, last_byte):
    bytestring = (''.join(r' '+hex(letter)[2:] for letter in data_raw[first_byte : last_byte]))
    print(intro + ": " + bytestring)

#pretend to be a vending machine - send a code, badge dumps status back
def vendo(): 
    vendo=bytearray.fromhex("536D6173683F000102ffc3")
    ser.flushInput()
    ser.write(vendo)
    data_raw=ser.readline()
    data_array = data_raw.decode("all-escapes").split("\\x")
    expected_header = '536d6173683f' # Smash?

    # definitions for decoder
    if ''.join(data_array[0:7]) == "536d6173683f":
        print("[+] Correct Header")
        print("")
    else:
        print(''.join(data_array[0:7]))
        exit()

    # Status
    badge_status = data_array[8]
    if badge_status == "01":
        print("[+] Con Start: " + badge_status)
    if badge_status == "02":
        print("[-] Sick: " + badge_status)

    # Ping Type
    badge_ping_type = data_array[9]
    if badge_ping_type == "02":
        print("[+] Data Dump")
    else:
        print("[-] Unknown Packet Type")

    # Badge ID
    badge_id = data_array[9:11]
    print("Badge ID: + " + ''.join(badge_id))

    # Badge Status Flags
    badge_status_flags = data_array[11]
    print("Badge Status Flags: " + badge_status_flags)

    print(data_array)
    
    
# Checksum calculator from carfucar
def write_this(b_id: int) -> bytes:
    header = b'Smash?'
    badge_id = 0
    header_checksum = 571
    f1 = (b_id >> 16) & 0xFF
    #print(f"f1: {f1:x}")
    f2 = (b_id >> 8) & 0xFF
    #print(f"f2: {f2:x}")
    f3 = (b_id >> 0) & 0xFF
    #print(f"f3: {f3:x}")
    b_ = b_id.to_bytes(3, 'big')
    cs = (header_checksum + f1 + f2 + f3) & 0xFF
    cs += 1
    cs = (~cs) & 0xFF
    cs = abs(cs)
    print(cs)
    cs += 1
    cs = (cs) & 0xFF
    cs_b = cs.to_bytes(1, 'big')
    return header + b'\x01' + b_ + cs_b

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

def reset_badge():
    ser.flushInput()
    ser.flushOutput()
    reset_badge_evil=bytearray.fromhex("536d6173683f00deadbeef29d6a2ec")
    ser.write(reset_badge_evil)

def start_con():
    ser.flushInput()
    ser.flushOutput()
    start_con_flag=bytearray.fromhex("536d6173683f010002fec4")
    ser.write(start_con_flag)

def jackpot():
    for i in range(000,800, 1):
        a = write_this(i)
        print(f"sending: {a.hex()}")
        ser.write(a)
        time.sleep(.1)
        ser.write(a)
        ser.write(a)
        ser.write(a)
        time.sleep(.1)
        ser.write(a)
        time.sleep(.7)
        
def cryptoStuff(crypt, key):

    const_rounds = 26
    const_wbytes = 5
    
    for i in range(const_rounds):
        c0 = crypt[const_wbytes]
        k0 = key[const_wbytes]
        ac = 0
        ak = 0
        for j in range(const_wbytes-1):
            ac += crypt[j] + crypt[(j+1) + const_wbytes]
            crypt[j+const_wbytes] = (ac ^ key[j])&0xFF
            ac = ac >> 8
            
            ak = key[j] + key[(j+1) + const_wbytes]
            key[j+const_wbytes] = (ac ^ key[j])&0xFF
            ak = ak >> 8
        
        ac += crypt[const_wbytes-1] + c0
        crypt[(const_wbytes-1) + const_wbytes] = (ac ^ key[const_wbytes-1])&0xFF
        
        ak += key[const_wbytes-1] + k0
        key[(const_wbytes-1)+const_wbytes] = ak&0xFF
        key[const_wbytes] =  (key[const_wbytes]^i)&0xFF
        
        c0 = crypt[const_wbytes-1]
        k0 = key[const_wbytes-1]
        for j in range(const_wbytes-1, 0, -1):
            crypt[j] = (((crypt[j] << 3) | (crypt[j-1] >> 5)) ^ crypt[j + const_wbytes])&0xFF
            key[j] = (((key[j] << 3) | (key[j-1] >> 5)) ^ key[j + const_wbytes])&0xFF
        
        crypt[0] = (((crypt[0] << 3) | (c0 >> 5)) ^ crypt[const_wbytes])&0xFF
        key[0] = (((key[0] << 3) | (k0 >> 5)) ^ key[const_wbytes])&0xFF 
    
    return crypt

vendo()
#jackpot()
