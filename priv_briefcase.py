#!/usr/local/bin/python

'''
	[ Private Briefcase V2 ]
	Copyright (C) 2012, Cristi Constantin.
	All Rights Reserved.

	This new version is a little differend from the old version:
	- the briefcase is a Python Pickle;
	- the briefcase is accessed with a username and a password;
	- all files are encrypted, without exception;
	- the files are not stored inside the briefcase;
	- the files are not versioned;
'''

import os, sys
import time
import datetime
import cPickle as pickle

# External dependency.
from Crypto.Cipher import AES
from Crypto.Hash import MD4
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

'''
A briefcase contains 4 tables :
	system : some information about the briefcase
	users  : usernames and passwords
	files  : metadata about the files from the respective folder
	logs   : (optional) change logs

System is a dictionary with some metadata.

Users is a dictionary with user_id => usr (pbkdf2 hash with fixed salt), pwd (pbkdf2 hash),
	usr_salt, pwd_salt.
Logs is a dictionary with date-time => user_id, msg (encrypted).

A user can only decrypt his own files. He can see if there are other users
	with other files, but cannot know anything about the files.
Files is a list of: filename (encrypted), hash, salt,  user_id, labels (encrypted),
	compressed (yes/ no), date_created.
'''

#

class Briefcase:

	def __init__(self, filename, create=False, logging=False):
		'''
		Connect to one briefcase file.
		Neither the list of files, nor the logs can be decrypted,
		unless a user with a correct password is connected.
		With "create" option, the briefcase is created.
		'''

		self._filename = filename
		self._dict = {} # The main dictionary
		self._user_id  = None
		self._encr_key = None

		if create:
			if not os.path.exists(filename):
				self._dict['system'] = {'logging': logging, 'created': time.strftime("%Y-%b-%d %H:%M:%S")}
				self._dict['users']  = {}
				self._dict['files']  = {}
				self._dict['logs']   = {}
				# Commit...
				self._dump()
			else:
				raise Exception('Create briefcase error! File `%s` already exists! Exiting!' % filename)
		else:
			if os.path.exists(filename):
				self._dict = pickle.load(open(filename, 'rb'))
			else:
				raise Exception('Open briefcase error! File `%s` does not exist! Exiting!' % filename)


	def _dump(self):
		'''
		Save the main dictionary on HDD.
		'''
		pickle.dump(self._dict, open(self._filename, 'wb'), pickle.HIGHEST_PROTOCOL)
		return True


	def _encrypt(self, bdata, salt='^default-salt-for-logs$'):
		'''
		Encrypt some data.
		The master ENCR KEY is used for all data, but the salt is always differend.
		'''
		pwd = PBKDF2(password=self._encr_key, salt=salt, dkLen=32, count=1000)
		crypt = AES.new(pwd)
		padding = 'X' * ( (((len(bdata)/16)+1)*16) - len(bdata) )
		return crypt.encrypt(bdata + padding)


	def _decrypt(self, bdata, salt='^default-salt-for-logs$'):
		'''
		Decrypt some data.
		The default salt is used only for logs.
		'''
		pwd = PBKDF2(password=self._encr_key, salt=salt, dkLen=32, count=1000)
		crypt = AES.new(pwd)
		return crypt.decrypt(bdata)


	def connect(self, username, password, create=False):
		'''
		Submit username and password and if they match,
		update the list of Files and Logs for the user.
		The user and pwd are required, both on access and creation.
		With "create" option, a new user is created.
		'''

		# On creating new user...
		if create:
			# If no users, ID = 1
			if not self._dict['users']:
				self._user_id = 1
			# Get the biggest user ID
			else:
				self._user_id = max( self._dict['users'].keys() ) + 1

			# Create salts
			usr_salt = get_random_bytes(32)
			pwd_salt = get_random_bytes(32)

			# Create encrypted usr and pwd
			usr = PBKDF2(password=username, salt='1private-briefcase!', dkLen=32, count=5000)
			pwd = PBKDF2(password=password, salt=pwd_salt, dkLen=32, count=5000)

			# Commit...
			self._dict['users'][self._user_id] = {
				'usr': usr, 'pwd': pwd, 'usr_salt': usr_salt, 'pwd_salt': pwd_salt
			}

		# On authenticating...
		else:
			# This generates an encrypted username, same as the one stored in the briefcase
			usr = PBKDF2(password=username, salt='1private-briefcase!', dkLen=32, count=5000)

			# If the encrypted username doesn't match with anything, it's an error
			if not usr in [ k['usr'] for k in self._dict['users'].values() ]:
				print('Sign-in error! Username `%s` does not exist! Exiting!' % username)
				return False

			# A few pointers for later
			self._user_id = [ k for k in self._dict['users'] if self._dict['users'][k]['usr'] == usr ][0]
			usr_salt = self._dict['users'][self._user_id]['usr_salt']
			pwd_salt = self._dict['users'][self._user_id]['pwd_salt']

			# At this point the username is valid, so check the password...
			if not PBKDF2(password=password, salt=pwd_salt, dkLen=32, count=5000) == \
				self._dict['users'][self._user_id]['pwd']:
				print('Sign-in error! The password does not match! Exiting!')
				return False

		# Generate key from username and password
		self._encr_key = PBKDF2(password=password+pwd_salt, salt=username+usr_salt, dkLen=32, count=2000)

		# Now that the encryption key is generated, write some logs
		now = datetime.datetime.today()
		if create:
			if self._dict['system']['logging']:
				self._dict['logs'][now.strftime("%Y-%b-%d %H:%M:%S.%f")] = {'usr_id': self._user_id,
				'msg': self._encrypt('Username created!') }
		else:
			if self._dict['system']['logging']:
				self._dict['logs'][now.strftime("%Y-%b-%d %H:%M:%S.%f")] = {'usr_id': self._user_id,
				'msg': self._encrypt('Username signed-in!') }

		self._dump()
		return True


	def show_logs(self):
		'''
		Print all logs for current user.
		'''
		if not self._user_id:
			print('Cannot decrypt logs! Must sign-in first!')
			return False

		for k in self._dict['logs']:
			log = self._dict['logs'][k]
			# Skip other users
			if log['usr_id'] != self._user_id:
				continue
			# Print the log. Ignore the microseconds
			print('%s :: %s' % (k.split('.')[0], self._decrypt(log['msg'])) )

		return True


	def join_briefcase(self, filename, usr, pwd, overwrite=False):
		'''
		Copy the Files from another briefcase, using a correct combination of usr + pwd.
		If there are files with the same name, with overwrite enabled,
		the files here are updated. Else, the files here are kept.
		The files are encrypted using the usr + pwd from the current briefcase, not the remote one.
		'''
		pass


	def add_file(self, filename, overwrite=False):
		'''
		Adds 1 file in the Files dictionary and encrypts the data.
		The original file is not deleted.
		'''
		pass


	def remove_file(self, filename):
		'''
		Remove 1 file in the Files dictionary and delete the encrypted file.
		'''
		pass


	def decrypt_file(self, filename):
		'''
		Decrypt a file from the Briefcase folder, using the encr_key.
		'''
		pass

#

# Eof()
