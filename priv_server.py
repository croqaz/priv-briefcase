#!/usr/local/bin/python

'''
	[ Private Briefcase V2 ]
	Copyright (C) 2012, Cristi Constantin.
	All Rights Reserved.
'''

import os, sys

from bottle import run, route, get, post, debug, template
from bottle import request, response, redirect, static_file

from priv_briefcase import Briefcase


B = None
USR = None
FILE = 'test/test1.pkl'

# # # # #

def connect(usr=0, pwd=0):

	global B, USR
	USR = usr
	#
	if not os.path.exists(FILE):
		B = Briefcase(FILE, create=True, logging=True)
		print 'Created:', B, '\n'
	else:
		B = Briefcase(FILE, create=False, logging=True)
		print 'Opened:', B, '\n'
	#
	B.connect(usr, pwd, create=False)


@route('/')
@route('/index')
@route('/index/')
def index():

	global B
	if not B:
		redirect('/login')
	#
	files = B.list_files()
	return template('tmpl/basic.htm', user=USR, files=files)


@route('/view/<fname>')
def view(fname):

	global B
	if not B:
		redirect('/login')
	#
	return template('tmpl/view.htm', fname=fname)


@route('/login')
@route('/login/')
def login():

	return template('tmpl/login.htm')


@post('/login')
@post('/login/')
def login_post():

	usr = request.POST.get('usr', '').strip()
	pwd = request.POST.get('pwd', '').strip()
	#
	if usr and pwd:
		connect(usr, pwd)
	#
	redirect('/index')


@route('/preview/<fname>')
def preview(fname):

	global B
	if not B:
		redirect('/login')
	#
	finfo = B.decrypt_file(fname)
	response.content_type = 'image/jpeg'
	return finfo['preview']


@route('/full/<fname>')
def full(fname):

	global B
	if not B:
		redirect('/login')
	#
	finfo = B.decrypt_file(fname)
	response.content_type = 'image/jpeg'
	return finfo['data']


@route(':filename#.*\.png|.*\.gif|.*\.jpg|.*\.ico|.*\.css|.*\.js#')
def server_static(filename=None):

	return static_file(filename, root=os.getcwd())

# # # # #

if __name__ == '__main__':

	debug(True)
	run(host='localhost', port=333, reloader=True)
