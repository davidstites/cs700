#!/bin/bash

sudo airmon-ng start wlan0
sudo harvestd -n wlan0 -f /home/pi/addresses.sqlite