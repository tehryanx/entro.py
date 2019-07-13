#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
import argparse
import os

### This tool will search a file or set of files for high entropy strings
### trufflehog was heavily plundered in the making of this tool. 

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"
threshold = 20
b64_minimum = 4.5
hex_minimum = 3.0
recurse = False
filename = None
verbose = False

def main():

	global threshold
	global b64_minimum
	global hex_minimum
	global verbose
	
	parser = argparse.ArgumentParser(description='Search files for strings with high shannon entropy.')
	group = parser.add_mutually_exclusive_group()
	group.add_argument('-f', '--filename', type=str, metavar="FILE", help='File to search.')
	group.add_argument('-d', '--directory', action="store_true", help='Search all files in the current directory. Use instead of -f')
	parser.add_argument('-r', '--recurse', action="store_true", help='Search directories recursively starting in the current directory. Use with -d')
	parser.add_argument('-m', '--minimum', type=int, metavar="", default=20, help='Minimum length of a string to consider')
	parser.add_argument('-v', '--verbose', action="store_true", help='Verbose output')
	parser.add_argument('--b64entropy', type=float, metavar="", default=4.5, help='Minimum shannon entropy to report a base64 string.')
	parser.add_argument('--hexentropy', type=float, metavar="", default=3, help='Minimum shannon entropy to report a hex string.')
	args = parser.parse_args()
	
	if args.filename == None:    # if no filename is supplied we search all files in the current directory. 
		args.directory = True
	else:
		filename = args.filename
	
	threshold = args.minimum
	b64_minimum = args.b64entropy
	hex_minimum = args.hexentropy
	verbose = args.verbose
	
	# recursive directory scan
	if args.directory and args.recurse:
		for root, dir, files in os.walk("."):
			for file in files:
				result = find_entropy(root+"/"+file)
				for i in result:
					print i
					
	# all files in current dir
	elif args.directory and not args.recurse: 
		files = [file for file in os.listdir('.') if os.path.isfile(file)]
		for file in files:
			result = find_entropy(file)
			for i in result:
				print i
		
	# only supplied file
	else: 
		result = find_entropy(args.filename)
		for i in result:
			print i

def get_strings_of_set(word, char_set):
	""" 
	return all strings in word with length > threshold that contain only characters in char_set (from trufflehog)
	"""
	
	count = 0
	letters = ""
	strings = []
	for char in word:
		if char in char_set:
			letters += char
			count += 1
		else:
			if count > threshold:
				strings.append(letters)
			letters = ""
			count = 0
	if count > threshold:
		strings.append(letters)
	return strings

def shannon_entropy(data, iterator):
	"""
	return the shannon entropy value for a given string (borrowed from trufflehog)
	Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
	"""
	if not data:
		return 0
	entropy = 0
	for x in iterator:
		p_x = float(data.count(x))/len(data)
		if p_x > 0:
			entropy += - p_x*math.log(p_x, 2)
	return entropy

def find_entropy(filename):
	"""
	step through a file line by line finding b64/hex blobs and measuring their entropy. 
	from trufflehog but modified.
	"""
	strings_found = []  # store detected secrets
	line_counter = 0 # this will let us record what line a secret was found on
	printable = [] # this will store the printable result
	
	with open(filename) as f:	
		lines = f.readlines()
		
	for line in lines: # step through each line
	
		for word in line.split(): # look at each word.
			base64_strings = get_strings_of_set(word, BASE64_CHARS) # get b64 blobs
			hex_strings = get_strings_of_set(word, HEX_CHARS) # get hex blobs
			for string in base64_strings: # step through each b64 string
				b64_entropy = shannon_entropy(string, BASE64_CHARS) # calculate entropy
				if b64_entropy > b64_minimum: # if entropy is significant
					strings_found.append(string) # record string
					if verbose:
						p = "\n-----------\nFile: " + filename + "\nLine: " + str(line_counter) + "\nType: Base64\nShannon Entropy: " + str(b64_entropy) \
							+ "\nSecret: " + string + "\nFull Line:\n\t" + line.strip()
					else:
						p = "\n"+ filename + " : " + str(line_counter) + " : " + string
					printable.append(p)
			for string in hex_strings: # step through each hex string
				hex_entropy = shannon_entropy(string, HEX_CHARS) # calculate entropy
				if hex_entropy > hex_minimum: # if entropy is significant
					strings_found.append(string)
					if verbose:
						p = "\n-----------\nFile: " + filename + "\nLine: " + str(line_counter) + "\nType: HEX\nShannon Entropy: " + str(hex_entropy) \
							+ "\nSecret: " + string + "\nFull Line:\n\t" + line.strip()
					else:
						p = "\n"+ filename + " : " + str(line_counter) + " : " + string
					printable.append(p)

			
		line_counter += 1
	return printable
	
if __name__ == "__main__":
    main()
	

	