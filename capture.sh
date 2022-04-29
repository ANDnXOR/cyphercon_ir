#!/bin/bash
stty -F /dev/ttyUSB0 raw -echo -echoe -echok 4800
cat /dev/ttyUSB0 | xxd -c 1