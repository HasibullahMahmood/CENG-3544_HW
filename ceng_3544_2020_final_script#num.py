#!/usr/bin/python3

# Import relevant modules
import os
import subprocess
from subprocess import Popen
import time, threading
import hashlib
from cryptography.fernet import Fernet
import getpass
import shutil
import sys
from shutil import copyfile


# Generate key
def gen_key():	
	key = Fernet.generate_key()
	return key

# Given file-name and path, read a file
def read_file(file_name, path='.'):
	file = open(path + "/" + file_name, 'r')
	file_content = file.read()
	file.close()
	return file_content

# Given file-content, file-name and path, write to a file
def write_file(file_content, file_name, path='.'):
	file = open(path + "/" + file_name, 'w')
	file.write(file_content)
	file.close()

# Run bash script commands and return the output
def run(command):
  # Create a subprocess
	p = subprocess.run([command],shell=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  # If command is executed successfully, return standart output, else standart error
	if p.returncode == 0:
		return p.stdout	
	else:
		return p.stderr

# Encrypt the plaintext by given key and return ciphertext 
def encrypt(plaintext, key):
	# create Fernet object
	cipher = Fernet(key)
  # Encode and Decode are used to convert byte to string and vice versa
	cipher_text = cipher.encrypt(plaintext.encode()).decode()
	return cipher_text

# Decrypt ciphertext by given key and return plaintext
def decrypt(cipher_text, key):
	# create Fernet object
	cipher = Fernet(key)
  # Encode and Decode are used to convert byte to string and vice versa
	plaintext = cipher.decrypt(cipher_text.encode()).decode()
	return plaintext

# Calculate hash for given text by sha256 algorithm and return the hash
def hash(text): 
 	#Hash the file with sha256
	sha256Hashed = hashlib.sha256(text.encode('utf-8')).hexdigest()
	return sha256Hashed


# Create passwd_encrypted.txt and file_sizes_encrypted.txt files
def create_system_status(key, path="."):
	# Get file sizes in root 1 depth level
	file_sizes = run("cd / && du -h --max-depth=1 --block-size=1M 2> /dev/null | sort -r -h")
	# Encrypt file_sizes by given key
	file_sizes_encrypted = encrypt(file_sizes, key)
	# Write file_sizes to a file
	write_file(file_sizes_encrypted, "file_sizes_encrypted.txt", path)

	# Get content of passwd file
	passwd_content = run("cat /etc/passwd")
	# Encrypt passwd_content by given key
	passwd_content_encrypted = encrypt(passwd_content, key)
	# Write encrypted content to a file
	write_file(passwd_content_encrypted, "passwd_encrypted.txt", path)

	# Calculate Hash for both variables (for integerity purpose)
	file_sizes_encrypted_hash = hash(file_sizes_encrypted)
	passwd_encrypted_hash = hash(passwd_content_encrypted)

	# Create a variable joining both hashes
	hashes = "file_sizes_encrypted_hash: " + file_sizes_encrypted_hash + "\npasswd_encrypted_hash: " + passwd_encrypted_hash
	
	# Write hashes to a file
	write_file(hashes, "hashes.txt", path)

# Check for new added or deleted accounts in passwd file
def check_account(key, path="."):
	# Read encrypted passwd file 
	passwd_encrypted = read_file("passwd_encrypted.txt", path)
	# Decrypt it
	passwd_decrypted = decrypt(passwd_encrypted, key)
	# Get current passwd content
	current_passwd = run("cat /etc/passwd")
	# Split them by newline
	passwd_decrypted = passwd_decrypted.split("\n")
	current_passwd = current_passwd.split("\n")
	# Compare both
	# Is there any line deleted from passwd file?
	output1 = [line for line in passwd_decrypted if line not in current_passwd]
	# Is there any new line added to passwd file?
	output2 = [line for line in current_passwd if line not in passwd_decrypted]
	# Append the results to result variable
	result = ""
	if len(output1) > 0:
		result = "Following line(lines) are deleted from passwd file:\n"
		for i in range(len(output1)):
			result += output1[i] + "\n"
	if len(output2) > 0:
		result += "Following line(lines) are added to passwd file:\n"
		for i in range(len(output2)):
			result += output2[i] + "\n"
	# Check if there is no change
	if len(output1) == 0 and len(output2) == 0:
		result = "No change in passwd file."
	return result

# Check whether files sizes increased or decreased
def check_file_sizes(key, path="."):
	# Read encrypted file_sizes.txt file 
	file_sizes_encrypted = read_file("file_sizes_encrypted.txt", path)
	# Decrypt it
	file_sizes_decrypted = decrypt(file_sizes_encrypted, key)
	# Get current file sizes under root
	current_file_sizes = run("cd / && du -h --max-depth=1 --block-size=1M 2> /dev/null | sort -r -h")
	# Split them by newline
	file_sizes_decrypted = file_sizes_decrypted.split("\n")
	current_file_sizes = current_file_sizes.split("\n")
	
	# Check whether total files sizes changed or not
	if file_sizes_decrypted[0] == current_file_sizes[0]:
		result = "There is no change in files sizes"
	else:
		result = "The following changes happen to files sizes:\n"
	  # Extract changed files
		output1 = list(set(current_file_sizes) - set(file_sizes_decrypted))
		output2 = list(set(file_sizes_decrypted) - set(current_file_sizes))
		# Combine result to a string variable
		for i in range(len(output1)):
		    result += output1[i] + " \n"
		for i in range(len(output2)):
		    result += output2[i] + " \n"
	return result



def create_system_summary(key, path="."):
	print('Creating System Summary, Please wait...')
	summary = ""
	summary += "###################################################################################\n"
	summary += 'System Summary Report\n'
	# Get current date
	summary += run("echo $(date)")
	summary += '\nIs there any change in accounts(passwd) file?...\n'
	# Call check account function
	summary += check_account(key, path)

	# Look for failed logins
	summary += '\n\nFailure logins...\n'
	summary += run("grep failure /var/log/auth.log")

	# Sluggish system performance
	summary += '\n\nSystem Usage State...\n'
	# Get information of running processes
	summary += run("top -i -n 1 -b")

	# Excessive memory use
	summary += '\nCurrent memory state in MB...\n'
	summary += run("free -m")

	summary += '\nProgram per memory usage...\n'
	# Get 10 high memory used processes
	summary += run("ps -eo comm,pmem --sort -pmem | head -10")

	# Decrease in Disk space
	summary += '\nIs there any change in file sizes?...\n'
	summary += check_file_sizes(key, path)
		
	# Unusual files like the files starts with .
	summary += '\n\nUnusual files like the files start with \".\"\n\n'
	summary += run("sudo find / -name '.*' | tail -10")

	#Network usage per process
	#run("sudo nethogs")
	# Get terminal screenshot
	#run("scrot -u")
	
	#Unusual schedualed tasks
	summary += '\nSchedualed jobs by UID \"0\" ...\n'
	summary += run("sudo crontab -u root -l")
	
	print("System Summary is created Successfully.\n")
	return summary

# Return USB path and check whether it exists or not
def get_usb_path():
	username = getpass.getuser()
	path = "/media/" + username
	usb_name = input("Please enter USB name:")
	path = path + "/" + usb_name
	if(not(os.path.isdir(path))):
		print("The USB "+ usb_name + " does not exist!")
		sys.exit()
	else:
		return path

# Given time and key, create system summary 
def run_periodically(seconds, key):
    #print(seconds)
    # Print current time
    print(time.ctime())
    # Get old encrypted system summary, decrypt it and join with new summary
    old_encrypted_summary = read_file("encrypted_system_summary.txt")
    old_decrypted_summary = decrypt(old_encrypted_summary, key)
    summary = create_system_summary(key)
    new_summary = summary + "\n" + old_decrypted_summary
    # Encrypt the summary and write to a file
    cipher_text = encrypt(new_summary, key)
    write_file(cipher_text, "encrypted_system_summary.txt")
	
    # Callback after given time
    threading.Timer(int(seconds), run_periodically,[seconds, key]).start()

# Check file integerity by comparing hashes
def check_files_integerity(hash1, hash2):
  # Calculate hashes for both encrypted files
	file_sizes_encrypted_hash = hash(read_file("file_sizes_encrypted.txt"))
	passwd_encrypted_hash = hash(read_file("passwd_encrypted.txt"))

	# Compare hashes
	if not (file_sizes_encrypted_hash == hash1 and passwd_encrypted_hash == hash2):
		print("Warning: The hashes are not the same, encrypted files might have changed.")
		print("Please create system-status again or enter correct hashes!!")
		sys.exit()
		
	else:
		return True

		
# Update task schedular file to create system summary periodically
def update_crontab():
	a = "line=\"*/2 * * * * " + os.getcwdb().decode() + "/script.py\""
	b = "(crontab -u " + username + " -l; echo \"$line\" ) | crontab -u " + username + " -"
	p = Popen(a + " && " + b, shell=True)
	p.wait()
	if p.wait() == 0:
		print("Crontab successfully updated.")

# Driver funciton
def main():
  # Get current username
	username = getpass.getuser()
  # Ask user to select an option
	userInput = input("\nWelcome " + username.capitalize() + 
	"!\nPlease enter one of the following numbers:\n" + 
	"\t1. Generate a new key\n" + 
	"\t2. Capture system current-status\n" +
	"\t3. Capture system current-status in USB\n" +
	"\t4. Create system-summary\n" + 
	"\t5. Create system-summary periodically every 1.5 minute\n" + 
	"\t6. Decrypt system-summary\n")

  # If option 1 is selected, generate a new key, write to a file and exit
	if(userInput == "1"):
		key = gen_key()
		write_file(key.decode(), "key.key", path='.')
		print("A new key is generated successfully.")
		sys.exit()
	# If option 2 is selected, ask for key and create system status
	elif(userInput == "2"):
		key = input("Please enter your key: ")
		print("Processing, please wait...")
		create_system_status(key, path=".")
		print("file_sizes_encrypted.txt and passwd_encrypted.txt are created successfully.")
		sys.exit()

	# If option 3 is selected, create current system status to a given USB
	elif(userInput == "3"):
	  # Get USB path
		path = get_usb_path()
	  # Ask for the key
		key = input("Please enter your key: ")
		print("Processing, please wait...")
		create_system_status(key, path)
		current_path = os.getcwdb().decode()
		# Take a copy of files to the local disk
		run("cp " + path + "/file_sizes_encrypted.txt " + current_path + "/file_sizes_encrypted.txt")
		run("cp " + path + "/passwd_encrypted.txt " + current_path + "/passwd_encrypted.txt")
		run("cp " + path + "/hashes.txt " + current_path + "/hashes.txt")
		print("file_sizes_encrypted.txt and passwd_encrypted.txt are created successfully.")
		sys.exit()
	
	# If option 4 is selected, then create system summary		
	elif(userInput == "4"):
		path = "./"
	  # Check whether system status files are available in the local disk
		if(not (os.path.isfile(path + "file_sizes_encrypted.txt") and os.path.isfile(path + "passwd_encrypted.txt"))):
			print("System status files are not found, please create system-status first #2")
			sys.exit()
		else:
			# Get hashes to compare with calculated hashes (Integerity purpose)
			hash1 = input("Please enter the hash number for file_sizes_encrypted: ")
			hash2 = input("Please enter the hash number for passwd_content_encrypted: ")

			# If there is no change in system status files
			if check_files_integerity(hash1, hash2):
				key = input("Please enter the key: ")
				summary = create_system_summary(key)
				cipher_text = encrypt(summary, key)
				write_file(cipher_text, "encrypted_system_summary.txt")
				print("Encrypted system summary is created successfully.")
				sys.exit()
	
	# Create system summary every 1.5 minute periodically			
	elif(userInput == "5"):
		hash1 = input("Please enter the hash number for file_sizes_encrypted: ")
		hash2 = input("Please enter the hash number for passwd_content_encrypted: ")
		if check_files_integerity(hash1, hash2):
			key = input("Please enter the key: ")
			run_periodically(90, key)
			#update_crontab()
			
	# If option 6 is selected, then decrypt system summary by the given key
	elif(userInput == "6"):
			if(not (os.path.isfile("./" + "encrypted_system_summary.txt"))):
				print("System summary file is not found, please create system-summary first #4")
			else:
				key = input("Please enter the key: ")
				cipher_text = read_file("encrypted_system_summary.txt")
				plaintext = decrypt(cipher_text, key)
				write_file(plaintext, "decrypted_system_summary.txt")
				print("The system-summary is decrypted successfully.")
				sys.exit()
				
	else:
		print("The number you have entered is incorrect!")
		sys.exit()
		




# Driver
main()
