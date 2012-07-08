#!usr/bin.ruby

=begin
	[ Private Briefcase V2 ]
	Copyright (C) 2012, Cristi Constantin.
	All Rights Reserved.

	This new version is a little differend from the old version:
	- the briefcase is a Python Pickle;
	- the briefcase is accessed with a username and a password;
	- a user can only access his own files;
	- all files are encrypted, without exception;
	- the files are not stored inside the briefcase;
	- the files are not versioned;
=end

require "openssl"
require 'base64'
require "zlib"

=begin
A briefcase contains 4 tables :
	system : some information about the briefcase
	users  : usernames and passwords
	files  : metadata about the files from the respective folder
	logs   : (optional) change logs

System is a dictionary with some metadata.
Logs is a dictionary with date-time => user_id, msg (encrypted).

Users is a dictionary with :
	user_id => usr (pbkdf2 hash with fixed salt),
	pwd (pbkdf2 hash),
	usr_salt and pwd_salt.

Files is a dictionary with :
	filename (encrypted with fixed salt) =>
	salt,
	hash (pbkdf2 with the salt),
	labels (encrypted with the salt),
	compressed (yes/ no),
	data (compressed and encrypted),
	user_id, ctime.

A user can only decrypt his own files. He can see if there are other users
	with other files, but cannot know anything about the files.
=end

#

class Briefcase

	def initialize(filename, create=false, logging=false)

		@_filename = filename
		@_dict = {}  # The main dictionary
		@_user_id  = nil
		@_encr_key = nil

		if create
			if not File.file? @_filename
				@_dict[:system] = {
					:logging => logging,
					:created => Time.now.strftime("%Y-%b-%d %H:%M:%S")
					}
				@_dict[:users]  = {}
				@_dict[:files]  = {}
				@_dict[:logs]   = {}

				_dump() # Commit...
			else
				fail "Create briefcase error! File `#{@_filename}` already exists! Exiting!"
			end

		else
			if File.file? @_filename
				puts "Loading..."
				_data = File.open(@_filename, 'rb').read
				@_dict = Marshal.load _data
				puts "Done!"
			else
				fail "Open briefcase error! File `#{@_filename}` does not exist! Exiting!"
			end

		end #if create

	end #initialize

#

	def _dump

		puts "Dumping in #{@_filename}..."
		_data = Marshal.dump @_dict
		File.new(@_filename, "w").puts(_data)
		puts "Done!"
		return true

	end #_dump


	def _encrypt(bdata, salt='^default-salt-for-logs$')

		if not @_user_id
			puts "Encryption error! There are no active users!"
			return false
		end

		o = OpenSSL::Cipher::Cipher.new("blowfish")
		o.encrypt
		o.key = Digest::SHA1.hexdigest(@_encr_key)
		o.iv  = salt

		r = o.update(bdata)
		r << o.final

	end #_encrypt


	def _decrypt(bdata, salt='^default-salt-for-logs$')

		if not @_user_id
			puts "Decryption error! There are no active users!"
			return false
		end

		o = OpenSSL::Cipher::Cipher.new("blowfish")
		o.decrypt
		o.key = Digest::SHA1.hexdigest(@_encr_key)
		o.iv = salt

		r = o.update(bdata)
		r << o.final

	end #_decrypt

#

	def connect(username, password, create=false)

		if create # On creating new user...

			# If no users, ID = 1
			if @_dict[:users] == {}
				@_user_id = 1
			# Get the biggest user ID
			else
				@_user_id = @_dict[:users].keys.max + 1
			end

			# Create salts
			usr_salt = OpenSSL::Random.random_bytes(32)
			pwd_salt = OpenSSL::Random.random_bytes(32)

			# Create encrypted usr and pwd
			usr = OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass=username, salt='1private-briefcase!', iter=9999, keylen=32)
			pwd = OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass=password, salt=pwd_salt, iter=9999, keylen=32)

			# Save to main dictionary...
			@_dict[:users][@_user_id] = {
				:usr=> usr, :pwd=> pwd, :usr_salt=> usr_salt, :pwd_salt=> pwd_salt,
			}

		else # On authenticating...

			# This generates an encrypted username, same as the one stored in the briefcase
			usr = OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass=username, salt='1private-briefcase!', iter=9999, keylen=32)

			# If the encrypted username doesn't match with anything, it's an error
			if not @_dict[:users].values.map{ |k| k[:usr] }.index(usr)
				puts "Sign-in error! Username `#{username}` does not exist! Exiting!"
				return false
			end

			# Find the user ID
			@_user_id = @_dict[:users].map{ |k,v| k if v[:usr] == usr }[0]

			# A few pointers for later
			usr_salt = @_dict[:users][@_user_id][:usr_salt]
			pwd_salt = @_dict[:users][@_user_id][:pwd_salt]

			# At this point the username is valid, so check the password...
			if OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass=password, salt=pwd_salt, iter=9999, keylen=32) !=
					@_dict[:users][@_user_id][:pwd]
				puts "Sign-in error! The password is not correct! Exiting!"
				return false
			end

		end #Create or Autenticate

		# Generate key from username and password
		# This key is the base for encrypting all files and logs
		@_encr_key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(pass=password+pwd_salt, salt=username+usr_salt,
			iter=2000, keylen=32)

		# Now that the encryption key is generated, write some logs
		now = Time.now
		if create
			if @_dict[:system][:logging]
				@_dict[:logs][now.strftime("%Y-%b-%d %H:%M:%S.%L")] = {
					:usr_id => @_user_id,
					:msg => _encrypt('Username created!')
				}
			end
		else
			if @_dict[:system][:logging]
				@_dict[:logs][now.strftime("%Y-%b-%d %H:%M:%S.%L")] = {
					:usr_id => @_user_id,
					:msg => _encrypt('Username signed-in!')
				}
			end
		end

		_dump() # Commit...
		return true

	end #connect


	def show_logs

		if @_user_id.nil?
			puts "Cannot decrypt logs! Must sign-in first!"
			return false
		end

		@_dict[:logs].each do |k, log|
			# Skip other users
			if log[:usr_id] != @_user_id
				next
			end
			# Print the log. Ignore the microseconds
			log = _decrypt(log[:msg])
			puts "#{k} :: #{log}"
		end

	end #show_logs


	def list_files

		# List the files, in order.
		files = []

		@_dict[:files].each do |k,v|
			fname = Base64.decode64(k)
			fname = _decrypt(fname, '0Default-s@lt-for-fileNames!')
			files << fname
		end

		return files.sort

	end #list_files


	def add_file(filename, labels=[], compress=false, included=false, overwrite=false)

		# Adds 1 file in the Files dictionary and encrypts the data.
		# The original file is not deleted.

		if @_user_id.nil?
			puts "Cannot add file! Must sign-in first!"
			return false
		end
		if not File.exists?(filename)
			puts "Cannot add file! File path `#{filename}` doesn't exist!"
			return false
		end
		if not labels.kind_of? Array
			puts "Cannot add labels! Labels must be an Array, you provided `#{labels.class}` !"
			return false
		end

		fname = File.basename(filename)	# Short filename
		encr  = _encrypt(fname, '0Default-s@lt-for-fileNames!')
		encr  = Base64.encode64(encr).rstrip

		if not overwrite and @_dict[:files][encr]
			puts "Cannot add file! The file exists already and you provided `overwrite = false` !"
			return false
		end

		now   = Time.now	# Date and Time
		salt  = OpenSSL::Random.random_bytes(32)	# Random salt
		bdata = File.open(filename, 'rb').read		# Original binary data
		fhash = Digest::MD5.hexdigest(bdata)		# Original data hash

		# Compress with ZLIB
		if compress
			z = Zlib::Deflate.new(6)
			bdata = z.deflate(bdata, Zlib::FINISH)
			z.close
		end

		bdata = _encrypt(bdata, salt)

		if not included
			path = File.dirname(filename) + "/" + encr
			File.open(path, 'wb').write(bdata)
		end

		@_dict[:files][encr] = {
			'labels'  => _encrypt(Marshal.dump(labels), salt),
			'ctime'   => now.strftime("%Y-%b-%d %H:%M:%S"),
			'user_id' => @_user_id,
			'salt'    => salt,
			'compressed'=> compress,
			'included'=> included,
			'hash'    => fhash,
			'data'    => bdata,
		}

		if included
			puts "Added file `#{fname}` inside the briefcase."
		else
			puts "Added file `#{fname}` outside the briefcase."
		end

		_dump() # Commit...
		return true

	end #add_file

end #class

#

#b = Briefcase.new('test.dump', true, true)
b = Briefcase.new("test.dump", false, true)
r = b.connect("user", "some secret password")
b.show_logs
b.add_file("README.md", labels=[], compress=true, included=true, overwrite=true)
puts "All files: #{b.list_files}."

# Eof()
