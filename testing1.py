
import os, sys
import glob
import shutil
import random
import unittest

from Crypto.Random import get_random_bytes
from priv_briefcase import *

#
FILE = 'test/test1.pkl'
#

class Test1(unittest.TestCase):

	def test_1_create(self):
		'''
		Test create briefcase and create user.
		'''
		# Cleanup
		try: shutil.rmtree('test')
		except: pass
		try: os.mkdir('test')
		except: pass

		b = Briefcase(FILE, create=True, logging=True)
		print 'Created:', b

		# Create 1 user
		r1 = b.connect('user', 'pass_pwd_ddd', create=True)
		print 'Created default user:', r1

		# Create more users
		for i in range(1, 10):
			r = b.connect('user_%i' % i, 'passwd_usr_%i' % i, create=True)
			print 'Created user %i:' % i, r
		del b

		# Final check
		self.assertTrue(r1 and r)


	def test_2_connect_correct(self):
		'''
		Test sign in with correct password.
		'''
		b = Briefcase(FILE)
		print 'Opened:', b
		# Log-in no 1
		r = b.connect('user', 'pass_pwd_ddd')
		print 'Sign-in user:', r
		# Log-in no 2
		r = b.connect('user_1', 'passwd_usr_1')
		print 'Sign-in user:', r
		self.assertTrue(r)


	def test_3_connect_wrong(self):
		'''
		Test sign in with a few wrong passwords.
		'''
		b = Briefcase(FILE, create=False)
		print 'Opened:', b

		results = []
		for i in range(25):
			r = b.connect('user', get_random_bytes(20))
			results.append(r)

		self.assertTrue( sum(results) == 0 )


	def test_4_show_logs(self):
		b = Briefcase(FILE)
		b.connect('user', 'pass_pwd_ddd')
		print 'Logs:'
		r = b.show_logs()
		del b
		self.assertTrue(r)

#

class Test2(unittest.TestCase):

	def test_1_create(self):
		'''
		Test create briefcase and create user.
		'''
		# Cleanup
		try: shutil.rmtree('test')
		except: pass
		try: os.mkdir('test')
		except: pass

		b = Briefcase(FILE, create=True, logging=True)
		print 'Created:', b
		# Create 1 user
		r1 = b.connect('user', 'some_long_password', create=True)
		print 'Created default user:', r1
		# Final check
		self.assertTrue(r1)


	def test_2_encrypt(self):
		'''
		Test encrypting files.
		Each file has labels and some files are compressed.
		'''
		b = Briefcase(FILE)
		b.connect('user', 'some_long_password')
		#
		files = glob.glob('/dos/Pics/Flickr/*.jpg')[:10]
		for fname in files:
			r = b.add_file(fname, labels=['image', 'jpg'], compress=random.choice([True, False]) )
		#
		print b.list_files()
		self.assertTrue(r)

	def test_3_decrypt(self):
		'''
		Test decrypting files. Some files are compressed.
		'''
		b = Briefcase(FILE)
		b.connect('user', 'some_long_password')
		#
		for fname in b.list_files():
			fd = b.decrypt_file(fname)
			print fname, 'compr=', fd['compressed'], 'incl=', fd['included'],\
				fd['ctime'], fd['labels']
			open('test/' + fname, 'wb').write(fd['data'])
		#
		self.assertTrue(True)

	def test_4_delete(self):
		'''
		Delete files outside briefcase.
		'''
		b = Briefcase(FILE)
		b.connect('user', 'some_long_password')
		#
		for fname in b.list_files():
			b.remove_file(fname)
		#
		self.assertTrue(b.list_files() == [])


	def test_5_encrypt_inside(self):
		'''
		Test encrypting files (included).
		Each file has labels and some files are compressed.
		'''
		b = Briefcase(FILE)
		b.connect('user', 'some_long_password')
		#
		files = glob.glob('/dos/Pics/Flickr/*.jpg')[-10:]
		for fname in files:
			r = b.add_file(fname, labels=['image', 'jpg'], included=True,
				compress=random.choice([True, False]) )
		#
		print b.list_files()
		self.assertTrue(r)

	def test_6_decrypt_inside(self):
		'''
		Test decrypting files (included). Some files are compressed.
		'''
		b = Briefcase(FILE)
		b.connect('user', 'some_long_password')
		#
		for fname in b.list_files():
			fd = b.decrypt_file(fname)
			print fname, 'compr=', fd['compressed'], 'incl=', fd['included'],\
				fd['ctime'], fd['labels']
			open('test/' + fname, 'wb').write(fd['data'])
		#
		self.assertTrue(True)

	def test_7_delete_inside(self):
		'''
		Delete files inside briefcase.
		'''
		b = Briefcase(FILE)
		b.connect('user', 'some_long_password')
		#
		for fname in b.list_files():
			b.remove_file(fname)
		#
		self.assertTrue(b.list_files() == [])

#

if __name__ == '__main__':

	print 'Starting...\n'
	suite = unittest.TestSuite()
	#suite.addTest(unittest.makeSuite(Test1))
	suite.addTest(unittest.makeSuite(Test2))
	unittest.TextTestRunner(verbosity=2).run(suite)
	print 'Done!\n'
