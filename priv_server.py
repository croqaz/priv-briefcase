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

# # # # #

def connect(bname, usr=0, pwd=0):

	global B, USR
	USR = usr
	#
	if not os.path.exists(bname):
		B = Briefcase(bname, create=True, logging=True)
		print 'Created:', B, '\n'
	else:
		B = Briefcase(bname, create=False, logging=True)
		print 'Opened:', B, '\n'
	#
	r = B.connect(usr, pwd, create=False)
	if not r:
		r = B.connect(usr, pwd, create=True)
		if r:
			print('Done creating user.\n')
	else:
		print('Sign in ok.\n')


@route('/login')
@route('/login/')
def login():

	return template('tmpl/login.htm')


@post('/login')
@post('/login/')
def login_post():

	bname = request.POST.get('bname', '').strip()
	usr = request.POST.get('usr', '').strip()
	pwd = request.POST.get('pwd', '').strip()
	#
	if bname and usr and pwd:
		connect(bname, usr, pwd)
	#
	redirect('/index')


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


@route('/view')
@route('/view/<fname>')
def view(fname=None):

	global B
	if not B:
		redirect('/login')
	if not fname:
		redirect('/index')
	#
	finfo = B.decrypt_file(fname, False)
	return template('tmpl/view.htm', fname=fname, labels=finfo['labels'], ctime=finfo['ctime'])


@post('/view')
@post('/view/<fname>')
def view_post(fname=None):

	global B
	if not B:
		redirect('/login')
	if not fname:
		redirect('/index')
	#
	new_fname  = request.POST.get('File', '').strip()
	new_labels = [x.strip() for x in request.POST.get('Labels', '').split(',')]
	#
	if fname != new_fname:
		B.rename_file(fname, new_fname)
		B.update_labels(new_fname, new_labels)
	elif new_labels:
		B.update_labels(fname, new_labels)
	#
	# After the re-name and re-label is done, redirect...
	if fname != new_fname:
		redirect('/view/' + new_fname)
	#
	finfo = B.decrypt_file(fname, False)
	return template('tmpl/view.htm', fname=fname, labels=finfo['labels'], ctime=finfo['ctime'])


@route('/del')
@route('/del/<fname>/<sure>')
def delete(fname=None, sure=None):

	global B
	if not B:
		redirect('/login')
	if not fname:
		redirect('/index')
	if not sure:
		redirect('/view/' + fname)
	#
	B.remove_file(fname)
	redirect('/index')


@route('/new')
@route('/new/')
def new():

	global B
	if not B:
		redirect('/login')
	#
	return template('tmpl/new.htm')


@post('/new')
@post('/new/')
def new_post():

	global B
	if not B:
		redirect('/login')
	#
	fobj = request.POST.get('fname', '')
	fname = fobj.filename
	bdata = fobj.value
	del fobj
	labels = [x.strip() for x in request.POST.get('labels', '').split(',')]
	compress  = request.POST.get('compress', '')
	included  = request.POST.get('included', '')
	overwrite = request.POST.get('overwrite', '')
	#
	r = B.add_file((fname, bdata), labels, compress, included, overwrite)
	if not r: print('Error adding file `{0}`!'.format(fname))
	#
	redirect('/index')


@route('/preview/<fname>')
def preview(fname):
	'''
	Preview thumbnail.
	'''
	global B
	if not B:
		redirect('/login')
	#
	finfo = B.decrypt_file(fname, False)
	response.content_type = 'image/jpeg'
	return finfo['preview']


@route('/full/<fname>')
def full(fname):
	'''
	View the full data.
	'''
	global B
	if not B:
		redirect('/login')
	#
	finfo = B.decrypt_file(fname, True)
	response.content_type = 'image/jpeg'
	return finfo['data']


@route('/admin')
@route('/admin/')
def admin():
	'''
	Administrate.
	'''
	global B
	if not B:
		redirect('/login')
	#
	logs = B.show_logs(False)
	return template('tmpl/admin.htm', user=USR, logs=logs)


@post('/admin')
@post('/admin/')
def admin():
	'''
	Administrate.
	'''
	global B
	if not B:
		redirect('/login')
	#
	objs = request.POST.getall('fname[]')
	#
	for fobj in objs:
		fname = fobj.filename
		bdata = fobj.value
		#
		labels = [x.strip() for x in request.POST.get('labels', '').split(',')]
		compress  = request.POST.get('compress', '')
		included  = request.POST.get('included', '')
		overwrite = request.POST.get('overwrite', '')
		#
		r = B.add_file((fname, bdata), labels, compress, included, overwrite)
		if not r: print('Error adding file `{0}`!'.format(fname))
	#
	logs = B.show_logs(False)
	return template('tmpl/admin.htm', user=USR, logs=logs)


@route(':filename#.*\.png|.*\.gif|.*\.jpg|.*\.ico|.*\.css|.*\.js#')
def server_static(filename=None):

	return static_file(filename, root=os.getcwd())

# # # # #

if __name__ == '__main__':

	debug(True)
	run(host='localhost', port=333, reloader=True)
