#### Python IOC Scanner ####
import os
from hashlib import md5, sha1, sha256 #We need to support three hash functions, md5, sha1, sha256
from datetime import datetime
# For getting date time information for generating report / log


def get_file_hashes(path):
	"""
	    This function gets the required hashes of the file specified by 'path'.
	    It computes the three required hashes, namely, md5, sha1, and sha256.
	    The resulting hashes of the file are returned as a tuple object.
	"""
	md5_hash = md5()
	sha1_hash = sha1()
	sha256_hash = sha256()
	
	with open(path, "rb") as file:
		while True:
			data = file.read(4096)
			if not data:
				break
			md5_hash.update(data)
			sha1_hash.update(data)
			sha256_hash.update(data)
			
	return (md5_hash.hexdigest(), sha1_hash.hexdigest(), sha256_hash.hexdigest())
	

def load_database(path):
	"""
	    This function responsible for parsing the database, specified by the 'path', getting all the hashes of the malicious files, as well as there corresponding descriptions.
	    It also checks, whether the hashes contained in the database, are free from unwanted characters. If it finds any problem with the hash, it will be reported to the console with line number for user to make a correction.
	    It returns a Python dictionary where the key is the hash from the database, and the value that the key maps to is the description.
	"""
	try:
		result = {}
		with open(path, "r") as db:
			c = 0
			for line in db:
				line = line.strip()
				if len(line) != 0:
					# If it is not an empty string
					if line[0] != '#':
						# It's not a comment, we can process it as a signature.
						data = line.split(";")
						data[0] = data[0].strip().lower()
						# Here we are checking if there are any illegal characters in the hash stored in the database. 
						if len(data[0].strip("0123456789abcdef")) != 0:
							print(f"Fatal error in database '{path}', at line number {c+1}")
							print("\"{data[0]}\", is not a valid hex-encoded string. ")
							return None
						result[data[0]] = "".join(data[1:]).strip()
				c += 1
		
		return result
					
	except:
		print(f"Error loading database '{path}' ")
		return None
		
def get_hash_desc(hash, database):
	"""
	    This function is responsible for finding whether a file hash has been found in the loaded database or not.
	    The first argument "hash" is a Python tuple object, that contains the calculated hashes of a particular file we want to check.
	    The second argument is the database which is a Python dictionary.
	    If a particular hash is not found in the dictionary a KeyError exception is thrown. We catch that exception and continue looping through "hash".
	    If a particular hash in "hash" is found, then we immediately return that hash along with its description. This is the indication that we found a matching hash in the database.
	    If no match is found we return a tuple (None, None) indicating we did not find any hash in "hash", matching in our database.
	    
	"""
	for h in hash:
		try:
			desc = database[h]
			return (desc, h)
		except KeyError as e:
			pass
	return (None, None)
	
# This function is used to skip special files, that are not required to be scanned. 

def is_skippable(path):
	try:
		target = os.path.realpath(path)
		status = os.stat(target)
		if status.st_size == 0:
			return 1
		if target.split("/")[1].lower().strip() == "proc":
			return 1
			
	except:
		return 2
	return 0
def scan_directory(path, database):
	"""
	    This function scans all the files in the directory specified by 'path', including all its subdirectories. 
	    It returns a tuple of Python lists, one containing the list of all malicious files, found with respective details of their hashes as well as descriptions.
	    The second list, is a list of files, that could not be read, due to some OS Error.
	"""
	malicious_files = []
	unable_to_open = []
	
	for root, dirs, files in os.walk(path):
		for file in files:
			full_path = os.path.join(root, file)
			ret = is_skippable(full_path)
			if ret == 1:
				continue
			elif ret == 2:
				unable_to_open.append(full_path)
				continue
			
			if os.path.isfile(full_path):
				os.system("clear")
				print(f"\t\tPython IOC Scanner\nScanning: '{full_path}'\n\nMalicious file(s) found: {len(malicious_files)}")
				try:
					desc, hash = get_hash_desc(get_file_hashes(full_path), database)
					if desc == None:
						continue
					malicious_files.append((full_path, desc, hash))
					
				except:
					
					unable_to_open.append(full_path)
				
	
	if len(malicious_files) == 0:
		malicious_files = None
	if len(unable_to_open) == 0:
		unable_to_open = None
	return (malicious_files, unable_to_open)
	
	
	
	
def main():
	"""
	   This is the main function of the Python application, IOC Scanner. 
	   It provides the interface to the user to use the script. 
	   It reports, the malicious files, if any and also creates the HTML log file. 
	"""
	database_file = "Hashesioc.txt"
	database = load_database(database_file)

	run = (database != None)
	while run:
		os.system("clear")
		
		print("\t\tPython IOC Scanner")
		print(f"* IOC Scanner will scan a particular directory for malicious files, based on the database '{database_file}' *")
		print("* To do a full system scan press '/' and hit ENTER (for Linux Systems)*")
		op = input("\nPlease type directory path to start scanning: ")
		if len(op.strip()) == 0:
			continue
		if os.path.isdir(op) == False:
			print(f"\nUnable, to open directory: '{op}' ")
			_ = input("\nPress ENTER to try again. ")
			continue
			
		malicious_files, unable_to_open = scan_directory(op, database)
		
		flag = 0
		os.system("clear")
		print("\t\tPython IOC Scanner")
		date = datetime.now()
		log_file = "logs_"+"".join("".join(str(date).split(":")).split("."))+".html"
		with open(log_file, "w") as log:
			log.write("<html>\n")
			log.write("<title>IOC Scanner Report on: {} </title>\n".format(date.strftime("%B %d %Y, %H:%M:%S")))
			log.write("<h1>IOC Scanner Report on: {} </h1>\n".format(date.strftime("%B %d %Y, %H:%M:%S")))
			log.write("<body>\n")
			if malicious_files == None:
				log.write(f"<font color=\"green\" > *** Congratulations: No malicious files were detected on scanning: '{op}' , as per current database. ***</font> <br>")
				print(f"*** Congratulations: No malicious files were detected on scanning: '{op}' , as per current database. ***")
			else:
				log.write(f"<font color=\"red\" > *** DANGER: {len(malicious_files)} malicious file(s) were detected on scanning: '{op}' ***</font> <br>")
				print(f"*** DANGER: {len(malicious_files)} malicious file(s) were detected on scanning: '{op}' ***")
				
				for file, desc, hash in malicious_files:
					print(f"\nFile: '{file}'\nDescription: '{desc}'\nHash: '{hash}' ")
					link = "\"https://www.virustotal.com/gui/home/search/\""
					log.write(f"<br> <font color=\"black\" > File: '{file}' <br> Description: '{desc}' <br> Hash: <strong> {hash} </strong> <br> <a href = {link}> Click to search on VirusTotal ! </a> <br> </font> ")
				unable_to_delete = []
				resp= input(f"\nDo you want to delete them all? (y/n): ")
				if resp.lower().strip()=='y':
					log.write(f"<br> <font color = \"green\"> *** User gave consent to delete these files. ***</font> <br>")
					for file, desc, hash in malicious_files:
						try:
							print(f"Deleting: '{file}' ")
							os.remove(file)
						except:
							unable_to_delete.append((file, desc, hash))
					
					if len(unable_to_delete) != 0:
						print(f"\n*** DANGER:  {len(unable_to_delete)} malicious file(s) could not be deleted. ***\n")
						log.write(f"<br> <font color = \"red\">*** DANGER:  {len(unable_to_delete)} malicious file(s) could not be deleted. ***</font> <br>")
						for file, desc, hash in malicious_files:
							print(f"\nFile: '{file}'\nDescription: '{desc}'\nHash: '{hash}' ")
							link = "\"https://www.virustotal.com/gui/home/search/\""
							log.write(f"<br> <font color=\"red\" > File: '{file}' <br> Description: '{desc}' <br> Hash: <strong> {hash} </strong> <br> <a href = {link}> Click to search on VirusTotal ! </a> <br> </font> ")
					else:
						print("\n*** All malicious files were deleted ***\n")
						log.write("<br> <font color=\"green\" >*** All malicious files were deleted *** </font>\n")
					
				else:
					log.write("<br> <font color=\"red\" > *** User did not give consent to delete these malicious file(s) ***</font>")
			
	
			if unable_to_open != None:
				log.write(f"<br> <font color=\"red\" >*** WARNING: {len(unable_to_open)} file(s) could not be opened for scanning. ***</font> <br>")
				print(f"*** WARNING: {len(unable_to_open)} file(s) could not be opened for scanning. ***\n")
				
				for file in unable_to_open:
					log.write(f"<font color=\"black\" > {file} </font> <br>")
					print(f"File: '{file}' ")
				
				
			
			log.write("</body>\n")
			log.write("\n<html>")
		
			
		print("\n* Scanning finished *")
		print(f"* Report has been saved to: '{log_file}' *")
		_ = input("\nPress ENTER to return to main menu...")
	
if __name__=="__main__":
	main()