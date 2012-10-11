#!/bin/bash

sudo apt-get update && sudo apt-get upgrade --yes

sudo apt-get install build-essential openssl libssl-dev git subversion flex bison iw wireless-tools sqlite3 libsqlite3-dev

sudo wget http://goo.gl/1BOfJ -O /usr/bin/rpi-update && sudo chmod +x /usr/bin/rpi-update
sudo /usr/bin/rpi-update

# get libpcap and tcpdump
wget http://www.tcpdump.org/release/libpcap-1.2.1.tar.gz
wget http://www.tcpdump.org/release/tcpdump-4.1.1.tar.gz
wget http://download.aircrack-ng.org/aircrack-ng-1.1.tar.gz

# build and install libpcap
tar -zxvf libpcap-1.2.1.tar.gz
rm libpcap-1.2.1.tar.gz
cd libpcap-1.2.1
./configure
make
sudo make install
cd ~

# build and install tcpdump
tar -zxvf tcpdump-4.1.1.tar.gz
rm tcpdump-4.1.1.tar.gz
cd tcpdump-4.1.1
./configure
make
sudo make install
cd ~

# build and install aircrack suite
tar -zxvf aircrack-ng-1.1.tar.gz
rm aircrack-ng-1.1.tar.gz
cd aircrack-ng-1.1
make
sudo make install
cd ~