**Documentation for IOC Scanner**

**Introduction**

The Python script "IOCScanner.py" is a script that can scan individual directories or perform a full system scan (root directory) , searching the directory/entire file system, for malicious files if any as per the database text file, "Hashesioc.txt", located in its working directory.
It also generates appropriate reports in the form of log files that are HTML documents, that contain very detailed information about the scan done.
The Python script converts the database text file into a Python dictionary and uses it to search for malicious hashes.

**How to run the Python script ?**

Simply, navigate to the location of the script using terminal. 
Type: **python IOCScanner.py**
and hit ENTER !


**How to initiate a scan ?**

When the script starts running, it will display all the instructions on the console, and ask for input from the user.
To run a test, you can type the path to a particular directory you wish to scan and hit ENTER.
For example, to scan the bin folder type:
/**bin**

and hit ENTER.
To scan the** full system** , type:
/
and hit ENTER.

To scan the **current working directory** , type:
.
and hit ENTER.

It is highly **recommended **that the script be run in **super user** mode.


**How database is parsed ?**

The Python script loads database from the file "Hashesioc.txt", and extracts the corresponding hash as well as the description separated by semi-colon ';' and puts them into a dictionary.
The file: "Hashesioc.txt", contains 10000+ sample information, and yet the IOC Scanner is very efficient in scanning!
I have updated that file, with **md5, sha1 and sha256** hashes of a few test files (ordinary harmless text files!) located in TestFiles directory, to demonstrate compromise detection capabilities.
It also checks, whether there are any illegal characters in the hash, and reports to the user, that there is an error in that particular line of the database.
The database parsing is done line by line. Lines beginning with "#" symbol are ignored by the script as they are considered as human readable comments.
A line in the database text file with a hash and description separated by semicolon is considered as a "sample", by the script.
It corresponds to a key, value pair for the abstract dictionary object returned.
As required, the database supports the three hash types **MD5, SHA-1 and SHA-256** .


**How are malicious hashes detected ?**

For every file encountered by the IOC Scanner, the three supported hashes are computed. They are stored as hex-encoded strings and packed into a three item, Python tuple object.
For every hash in the Python tuple object, we check if that particular hash is a valid key of the database dictionary.
If it's a valid key, then we have detected a malicious hash and then all the file details along with the description of the hash are stored in a tuple and appended to a list, that stores the details of every malicious file encountered within a tuple.
If we have not found a key for any of the three hashes, that comes from a single file, we deem it to be a "safe file", as per our database, because its hashes have not been found in our database, and hence that file is ignored and we proceed with the scanning.


**Where are report log files stored ?**

All generated report log files are HTML documents, that are stored in the current working directory of the script.


**How are malicious files handled ?**

When malicious files are detected, all their details, along with their absolute file paths are displayed on the console.
The script will ask the user a yes or no, question to delete those files.
If the user gives consent, the files will be deleted, permanently.
If for some reason, the files could not be deleted, all their details, along with their absolute paths, would be recorded in the report log file generated.


**Are there any additional dependencies, that needs to be installed ?**

There are no additional dependencies. It is standard Python code.
