#!/bin/bash
while true
do
    xxd -r -p $1 > /dev/ttyUSB0
done