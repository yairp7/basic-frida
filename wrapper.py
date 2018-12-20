import frida
import sys
import os

# Provide the application package name
app = sys.argv[1] 

def message_callback(message, data):
	print str(message['payload'])

# Read our code file
frida_code = None
with open(os.path.dirname(os.path.realpath(__file__)) + '/frida_script.js') as f: 
	frida_code = f.read()

if frida_code:
	# Get all devices connected
	devices = frida.get_device_manager().enumerate_devices()
	if devices and len(devices) > 0:
		usb_devices = []
		for device in devices: # Iterate through the devices
			if device.type == 'usb':
				usb_devices.append(device)
			if usb_devices and len(usb_devices) > 0:
				for device in usb_devices:
					pid = device.get_process(app).pid # Get the process id
					process = device.attach(pid) # Attach frida to the process
					# Create a script object from the provided code
					script = process.create_script(frida_code)
					# Create a javascript event listener to get callbacks from the 
					# javascript code to the python frida wrapper
					script.on('message', message_callback) 
					# Load the script into frida
			        script.load()
			     
sys.stdin.read()
