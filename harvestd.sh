#!/bin/bash

# always run this
echo "Starting harvestd"
#sudo iwconfig wlan0 essid AppleWiFi
#sudo iw wlan0 connect AppleWiFi
sudo airmon-ng start wlan0
/usr/bin/harvestd -f /home/pi/addresses.sqlite -n mon0

# handle the case of a user passing an argument
case "$1" in
	start)
		# probably could handle arguments here
		echo "Starting harvestd"
		sudo airmon-ng start wlan0
		/usr/bin/harvestd -f /home/pi/addresses.sqlite -n mon0
		;;
	stop)
		echo "Stopping harvestd"
		killall harvestd
		;;
	restart)
		# probably could handle arguments here
		echo "Stopping harvestd"
                killall harvestd
		echo "Starting harvestd"
                sudo airmon-ng start wlan0
                /usr/bin/harvestd -f /home/pi/addresses.sqlite -n mon0
                ;;
	*)
		echo "Usage: /etc/init.d/harvestd {start|stop|restart}
		exit 1
		;;
esac

exit 0
