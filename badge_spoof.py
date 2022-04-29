import serial
import time

# 53 6D 61 73 68 3F 01 00 01 B9 0A 
# 53 6D 61 73 68 3F 01 XX XX XX 33

# 53 6D 61 73 68 3F XX XX XX FF C3

header = b'Smash?'
badge_id = 0
header_checksum = 571




def write_this(b_id: int) -> bytes:
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
    

def make_cs(msg: bytes) -> bytes:
    t = 0
    for m in msg:
        t += m
    
    #t += 1
    t = (~t) & 0xFF
    t = abs(t) + 1
    return t.to_bytes(1, 'big')

bigmsg = b'\x53\x6D\x61\x73\x68\x3F\x00\x01\x02\xFF\xC3\x53\x6D\x61\x73\x68\x3F\x01\x02\x02\x0D\x07\x02\xDC\x01\x3B\x02\xFF\x00\x02\x42\xFF\xFF\x0E\x00\x2E\x74\x00\x4F\xA1\x00\x30\x9A\x00\x02\x01\xBC\x01\x6A\x00\x0F\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xB7\x0B\x02\x09\x83\xA7'


with serial.Serial() as ser:
    ser.baudrate = 4800
    ser.port = 'COM3'
    ser.open()
    a = bigmsg
    c = make_cs(a)
    # ser.write(a + c)
    print((a+c).hex())
    ser.write(a+c)
    
    '''
    for i in range(400,0, -1):
        a = write_this(i)
        print(f"sending: {a.hex()}")
        ser.write(a)
        time.sleep(0.7)
    '''
