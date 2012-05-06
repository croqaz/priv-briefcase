
import os, sys

from prv_briefcase import *


try: os.remove('test1.pkl')
except: pass


b = Briefcase('test1.pkl', create=True, logging=True)
print 'Created:', b
r = b.connect('user', 'pwddd', create=True)
print 'Created user:', r
del b


b = Briefcase('test1.pkl', create=False)
print 'Opened:', b
r = b.connect('user', 'pwddd', create=False)
print 'Sign-in user:', r

print '\nLogs:'
b.show_logs()
del b


print 'Done!'
