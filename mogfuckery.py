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


with serial.Serial() as ser:
    ser.baudrate = 4800
    ser.port = 'COM3'
    ser.open()
    for i in range(0,800, 1):
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