#!/usr/bin/env python3

import os.path, datetime
from os import path
import secrets
from decimal import Decimal, getcontext
import math
import datetime
import getpass
import glob
# IMPORTANT : binary_number_length must be greater than or equal to 8.

binary_number_length = 100
random_number_length = 100

# string contain all possible symbol.
s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'+ \
	'abcdefghijklmnopqrstuvwxyz'+ \
	' ' + '\n' + '\t' +\
	',.!:"$%?&()*+-/0123456789'+\
	'=@^{}|~`_[]\\<>#;' + "'"

# list contain all possible symbol.
symbols = list(s)

# currently working directory.
cwd = os.getcwd()
option_symbol = u"\u2325"
arrow_symbol = u"\u2BA9"
# function create a random 100 different binary sequence.
def random_bit(binary_number_length):
	# list store binary sequence.
	bit = []
	while len(bit) < 100:
		s = ''
		while len(s) < binary_number_length:
			s += str(secrets.choice([0,1]))
		# if string is already generated then pass the string and generate again.
		if s in bit:
			pass
		else:
			bit.append(s)
	return bit

# function converts characters to binary numbers.     
def char2bin(character, binary_number_list):
	s = ''
	for i in range(len(character)):
		s += binary_number_list[symbols.index(character[i])]
	return s
	
# function converts binary numbers to alphabets and other characters.
def bin2char(binary, binary_number_list):
	s = ''
	i = 0
	while i < len(binary):
		# takes binary_number_length characters at a time.
		one_character = binary[i:i+binary_number_length]
		s += symbols[binary_number_list.index(one_character)]
		i = i + binary_number_length
	return s	

# function return the digits after the decimal of the square root of an integer.

def sqr(x, decimal_place):
	int_part = str(int(math.sqrt(x)))
	int_part_len = len(int_part)
	decimal_place = int_part_len + decimal_place
	getcontext().prec = decimal_place
	s = str(Decimal(x).sqrt()).split(".")
	return s[1]

# The XOR gate.
def XOR(A,B):
	if A == B:
		return 0
	else:
		return 1

# Performs XOR between two input string.
def XOR_between_string(string_1,string_2):
	s = ''
	for i in range(len(string_1)):
		s += str(XOR(string_1[i],string_2[i]))
	return s	
	
# function convert word in to a number.
def word2num(word, random_number_list):
	s = 0
	for i in word:
		s += int(random_number_list[symbols.index(i)]) * word.index(i)
	return s
	
# extract the service name from a file.
def extract_service(service):
	if service.split('.')[0][:6] == 'random':
		return service.split('.')[0][7:]
	else:
		return service.split('.')[0]


# printing data from a file.	
def print_file(filename):
	path = cwd + '/decrypted/'
	os.chdir(path)
	
	f = open(filename,'r')
	g = f.readlines()
	# printing name.
	print(g[2], end ='')
	# printing url.
	print(g[3], end = '')
	# printing username.
	print(g[4], end = '')
	# printing password.
	print(g[1][:-1] + g[0], end ='')
	
# ---------- ENCRYPTION ----------

def encrypt_file(filename, username, user_password):

	path = cwd + '/random/'
	os.chdir(path)
	
	# generating random number.
	random_binary_text_file = open('random_' + filename,'w')
	for i in range(100):  
		random_binary_text_file.write('%d  %s\n'%(secrets.randbelow(10**random_number_length), random_bit(binary_number_length)[i]))
	random_binary_text_file.close()
	
	# opening random number file to read.
	random_binary_number_file = open('random_' + filename,'r')
	random_number_list = []
	binary_number_list = []
	
	for line in random_binary_number_file:
		field = line.split(" ")
		random_number = field[0]
		binary_number = field[2][:-1]
		random_number_list.append(random_number)
		binary_number_list.append(binary_number)
		
	path = cwd + '/decrypted/'
	os.chdir(path)
	
	# opening decrypted text file to encrypt.	
	decrypted_text_file = open(filename,'r')
	decrypted_text_file_str = decrypted_text_file.readlines()
	
	# the following string contain the binary sequence of the decrypted text.
	decrypted_text_bin = ''
	for i in decrypted_text_file_str:
		decrypted_text_bin += char2bin(i, binary_number_list)
		
	# length of the decrypted text.
	k = int(len(decrypted_text_bin)/binary_number_length)
	
	# username converted to number.
	username_decimal = sqr(word2num(username, random_number_list), k)
	# password converted to number.
	user_password_decimal = sqr(word2num(user_password, random_number_list), k)
	
	# username converted to binary.
	username_bin = char2bin(username_decimal, binary_number_list)
	# password converted to binary.
	user_password_bin = char2bin(user_password_decimal, binary_number_list)

	# string created with XOR between username and password.
	key_str_bin = XOR_between_string(username_bin, user_password_bin)
	
	# XOR between above string and the binary decrypted string.
	final_encrypted_str = XOR_between_string(key_str_bin, decrypted_text_bin)
	
	path = cwd + '/encrypted/'
	os.chdir(path)
	
	filename_number = str(word2num(filename, random_number_list))
	# write the encrypted string in a file.
	encrypted_text_file = open('encrypted_' + filename_number + '.txt','w')
	encrypted_text_file.write(final_encrypted_str)
	encrypted_text_file.close()

	path = cwd + '/decrypted/'
	os.chdir(path)
	
	# removes the decrypted text file.
	os.remove(filename)


	
# ---------- DECRYPTION ----------
def decrypt_file(filename, username, user_password):
	
	path = cwd + '/random/'
	os.chdir(path)
	
	# open file to read.
	random_binary_number_file = open('random_' + filename,'r')
	# list store random number from file.
	random_number_list = []
	# list store binary number from file.
	binary_number_list = []
	for line in random_binary_number_file:
		field = line.split(" ")
		random_number = field[0]
		# -1 is to avoid \n character at the end.
		binary_number = field[2][:-1]
		random_number_list.append(random_number)
		binary_number_list.append(binary_number)

	path = cwd + '/encrypted/'
	os.chdir(path)
	
	filename_number = str(word2num(filename, random_number_list))
	encrypted_text_file = open('encrypted_' + filename_number + '.txt','r')
	# following is a list of type ['110101'].
	encrypted_text_file_read = encrypted_text_file.readlines()
	# following is a string of type '110101'.
	encrypted_text_str = encrypted_text_file_read[0]

	# following is the length of encrypted text in decimal number.
	length_encrypted_text = int(len(encrypted_text_str)/binary_number_length)
	
	# username is converted to number and a square root of the number is calculated.

	username_decimal = sqr(word2num(username, random_number_list), length_encrypted_text)
	# password is converted to number and a square root of the number is calculated.
	user_password_decimal = sqr(word2num(user_password, random_number_list), length_encrypted_text)

	# username is converted to binary sequence.
	username_bin = char2bin(username_decimal, binary_number_list)
	# password is converted to binary sequence.
	user_password_bin = char2bin(user_password_decimal, binary_number_list)
	
	# XOR between username and password.
	key_str_bin = XOR_between_string(username_bin, user_password_bin)
	
	# XOR between above string and encrypted text.
	final_decrypted_text = XOR_between_string(encrypted_text_str, key_str_bin)
	
	# convert the decrypted text to human readable format. 
	final_decrypted_text_hrf = bin2char(final_decrypted_text, binary_number_list)
	
	path = cwd + '/decrypted/'
	os.chdir(path)
	
	# writes the decrypted text to the file decrypted text file.
	decrypted_text_file = open(filename,'w')
	decrypted_text_file.write(final_decrypted_text_hrf)
	decrypted_text_file.close()
	encrypted_text_file.close()
	
	path = cwd + '/encrypted/'
	os.chdir(path)
	
	os.remove('encrypted_' + filename_number + '.txt')
	
	path = cwd + '/random/'
	os.chdir(path)
	
	os.remove('random_' + filename)
			
# ask for username.	
username = input(option_symbol + ' Username :')	
# ask password from user.
user_password = getpass.getpass(option_symbol + ' Master password :')

while True:
	
	user_input = input('Enter \n'								+ arrow_symbol +' filename to decrypt \n'+ arrow_symbol + ' +p to add a new password\n' + arrow_symbol + ' +sn to add a secure note\n' + arrow_symbol + ' c to change your Master Password\n'+ arrow_symbol + ' -d to delete a file\n' + arrow_symbol + ' q to quit :')
	if user_input == 'q':
	
		path = cwd + '/decrypted/'
		os.chdir(path)
		
		dir = os.listdir(path)
		# checking if directory is empty.
		if len(dir) == 0:
			print('Done')
			break
		else:
			# list all decrypted text file.
			textfile_list = [f for f in glob.glob("*.txt")]
		
			# encrypting all decrypted file.
			for file in textfile_list:
				encrypt_file(file, username, user_password)
		break	
	# changing master password.	
	elif user_input == 'c':
	
		while True:
			enter_old_master_password = getpass.getpass('Enter old Master Password :')
			if enter_old_master_password == user_password:
				
				new_username = input('Enter username :')
				new_master_password = getpass.getpass('Enter new Master Password :')
				# all encrypted file will be re encrypted.
					
				# list all encrypted file.
				path = cwd + '/random/'
				os.chdir(path)
				# list all text file in random folder.
				textfile_list = [f for f in glob.glob("*.txt")]
				# list has all service name.
				service_list = []
				for file in textfile_list:
					service_list.append(extract_service(file))
					
				# decryptying all encrypted file using old master password.
				for file in service_list:
					decrypt_file(file + '.txt', username, user_password)
						
				# list all decrypted file.	
				path = cwd + '/decrypted/'
				os.chdir(path)
				all_decrypted_file_list	= [f for f in glob.glob("*.txt")]
					
				# encryptying all decrypted file using new master password.
				for file in all_decrypted_file_list:
					encrypt_file(file, new_username, new_master_password)
				username = new_username
				user_password = new_master_password
				print('Master password changed')
				break
			else:
				print('Enter old Master Password again')
					
	elif user_input == '+p':
		path = cwd + '/decrypted/'
		os.chdir(path)
		
		# l= [name, url, username, password]
		l = []
		
		# checking if the name already there.
		path = cwd + '/random/'
		os.chdir(path)
		# list all text file in random folder.
		textfile_list = [f for f in glob.glob("*.txt")]
		# list has all service name.
		service_list = []
		for file in textfile_list:
			service_list.append(extract_service(file))
			
		while True:	
			new_service_name = input('Enter a name : ')
			for name in service_list:
				if name == new_service_name:
					print('Name already present')
				else:			
					l.append(new_service_name)
					break
		
		new_url = input('Enter url (optional) : ')
		l.append(new_url)
		
		new_username = input('Enter username : ')
		l.append(new_username)
		
		new_password = input('Enter password : ')
		l.append(new_password)
		
		new_file = open(l[0] + '.txt', 'w')
		# writing password in the first line always to avoid repeating word.
		new_file.write(l[3] + '\n')
		new_file.write('Password - \n')
		new_file.write('Name - ' + l[0] + '\n')
		new_file.write('Url - ' + l[1] + '\n')
		new_file.write('Username - ' + l[2] + '\n')
		new_file.close()
		
	# adding secure note.	
	elif user_input == '+sn':
	
		# checking if the name already there.
		path = cwd + '/random/'
		os.chdir(path)
		# list all text file in random folder.
		textfile_list = [f for f in glob.glob("*.txt")]
		# list has all service name.
		service_list = []
		for file in textfile_list:
			service_list.append(extract_service(file))
		while True:	
			secure_note_name = input('Enter name :')
			if secure_note_name in service_list:
				print('Name already present')
			else:			
				break
				
		secure_note = input('Enter secure note : ')
		path = cwd + '/decrypted/'
		os.chdir(path)
		secure_note_file = open(secure_note_name + '.txt', 'w')
		secure_note_file.write(secure_note)
		secure_note_file.close()
		
	elif user_input == '-d':
			
		# checking if the file is there.
		path = cwd + '/random/'
		os.chdir(path)
		# list all text file in random folder.
		textfile_list_random = [f for f in glob.glob("*.txt")]
		
		# list all text file in decrypted folder.
		path = cwd + '/decrypted/'
		os.chdir(path)
		textfile_list_decrypted = [f for f in glob.glob("*.txt")]
		
		# list has all service name from random folder.
		service_list_random = []
		for file in textfile_list_random:
			service_list_random.append(extract_service(file))
			
		# list all service from decrypted folder.
		service_list_decrypted = []
		for file in textfile_list_decrypted:
			service_list_decrypted.append(extract_service(file))
			
		# deleting an encrypted file.	
		while True:	
			filename = input('Enter file name to delete :')
			if filename in service_list_random:
				decrypt_file(filename + '.txt', username, user_password)
				while True:
					verification = getpass.getpass('To delete the file re enter your master password :')
					if verification == user_password :
						path = cwd + '/decrypted/'
						os.chdir(path)
						os.remove(filename + '.txt')
						break
					else:
						print('re enter master password')
				break
				
			# deleting an decrypted file.	
			elif filename in service_list_decrypted:
				while True:
					verification = getpass.getpass('To delete the file re enter your master password :')
					if verification == user_password :
						path = cwd + '/decrypted/'
						os.chdir(path)
						os.remove(filename + '.txt')
						break
					else:
						print('re enter master password')
				break
			else:			
				print('re enter file name')
		
	else:
		decrypt_file(user_input + '.txt', username, user_password)
		print_file(user_input + '.txt')
