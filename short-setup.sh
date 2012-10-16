#!/bin/bash

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
