
import os, sys
import unittest

from Crypto.Random import get_random_bytes
from priv_briefcase import *

#

class Test1(unittest.TestCase):

	def test_1_create(self):
		'''
		Test create briefcase and create user.
		'''
		b = Briefcase('test1.pkl', create=True, logging=True)
		print 'Created:', b

		# Create 1 user
		r1 = b.connect('user', 'pass_pwd_ddd', create=True)
		print 'Created default user:', r1

		# Create more users
		for i in range(1, 10):
			r = b.connect('user_%i' % i, 'passwd_usr_%i' % i, create=True)
			print 'Created user %i:' % i, r
		del b

		self.assertTrue(r1 and r)


	def test_2_connect_correct(self):
		'''
		Test sign in with correct password.
		'''
		b = Briefcase('test1.pkl')
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
		b = Briefcase('test1.pkl', create=False)
		print 'Opened:', b

		results = []
		for i in range(25):
			r = b.connect('user', get_random_bytes(20))
			results.append(r)

		self.assertTrue( sum(results) == 0 )


	def test_4_show_logs(self):
		b = Briefcase('test1.pkl')
		b.connect('user', 'pass_pwd_ddd')
		print 'Logs:'
		r = b.show_logs()
		del b
		self.assertTrue(r)

#

if __name__ == '__main__':

	print 'Starting...\n'
	try: os.remove('test1.pkl')
	except: pass
	suite = unittest.TestLoader().loadTestsFromTestCase(Test1)
	unittest.TextTestRunner(verbosity=2).run(suite)
	print 'Done!\n'
