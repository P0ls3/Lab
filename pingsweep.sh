#!/bin/bash

for ip in $(seq 1 245); do
ping -c 1 10.11.1.$ip |grep "bytes from" |cut -d" " -f 4| cut -d":" -f1 &
done
