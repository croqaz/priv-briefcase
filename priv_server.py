#!/usr/local/bin/python

'''
	[ Private Briefcase V2 ]
	Copyright (C) 2012, Cristi Constantin.
	All Rights Reserved.
'''

import os, sys
import webbrowser
from bottle import run, route, get, post, debug
from bottle import response, redirect, template, static_file

from priv_briefcase import Briefcase

#

def connect():

	global B
	if B: return

	if not os.path.exists(FILE):
		B = Briefcase(FILE, create=True, logging=True)
		print 'Created:', B, '\n'
	else:
		B = Briefcase(FILE, create=False, logging=True)
		print 'Opened:', B, '\n'

	B.connect(USER, PWD, create=False)

#

@route('/')
@route('/index')
@route('/index/')
def index():

	connect()
	files = B.list_files()
	return template('basic.htm', user=USER, files=files)


@route('/preview/<fname>')
def preview(fname):

	connect()
	finfo = B.decrypt_file(fname)
	response.content_type = 'image/jpeg'
	return finfo['preview']


@route('/full/<fname>')
def full(fname):

	connect()
	finfo = B.decrypt_file(fname)
	response.content_type = 'image/jpeg'
	return finfo['data']

#

@route(':filename#.*\.png|.*\.gif|.*\.jpg|.*\.css|.*\.js#')
def server_static(filename=None):
	return static_file(filename, root=os.getcwd())

#

if __name__ == '__main__':
	B = None
	FILE = 'test/test1.pkl'
	USER = 'user'
	PWD = 'some long password...'

	#webbrowser.open_new_tab('http://localhost:333/')
	debug(True)
	run(host='localhost', port=333, reloader=True)
