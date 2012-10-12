#!/bin/bash

sudo apt-get update && sudo apt-get upgrade --yes

sudo apt-get install build-essential openssl libssl-dev git subversion flex bison iw wireless-tools sqlite3 libsqlite3-dev

sudo wget http://goo.gl/1BOfJ -O /usr/bin/rpi-update && sudo chmod +x /usr/bin/rpi-update
sudo /usr/bin/rpi-update

# install libpcap
tar -zxvf libpcap-1.2.1-arm6vl.tar.gz
rm libpcap-1.2.1-arm6vl.tar.gz
cd libpcap-1.2.1-arm6vl
sudo make install
cd ~

# install tcpdump
tar -zxvf tcpdump-4.3.1-arm6vl.tar.gz
rm tcpdump-4.3.1-arm6vl.tar.gz
cd tcpdump-4.3.1-arm6vl
sudo make install
cd ~

# install aircrack suite
tar -zxvf aircrack-ng-1.1-arm6vl.tar.gz
rm aircrack-ng-1.1-arm6vl.tar.gz
cd aircrack-ng-1.1-arm6vl
sudo make install
cd ~
sudo airodump-ng-oui-update

tar -zxvf cs700.tar.gz
rm cs700.tar.gz
cd cs700/harvest/harvestd

make
sudo make install
sudo chmod +x /usr/bin/harvestd

cd ../../

sudo cp harvestd.sh /etc/init.d/harvestd
sudo chmod 755 /etc/init.d/harvestd
sudo update-rc.d -f harvestd defaults

exit 0

#change passwd from raspberry

# cat to /etc/network/interfaces
#auto lo
#iface lo inet loopback
#iface eth0 inet dhcp
#allow-hotplug wlan0
#auto wlan0
#iface wlan0 inet dhcp
#wireless-essid  AppleWiFi
#wpa-roam /etc/wpa_supplicant/wpa_supplicant.conf
#iface default inet dhcp
