import flask
from flask import Flask, flash, redirect, request, render_template, session, url_for
from time import gmtime, strftime
import os
import json
from cloudant.client import Cloudant
from cloudant.query import Query
from datetime import datetime
import pytz
import hashlib
from cryptography.fernet import Fernet
import base64


# Recupero delle credenziali di Cloudant dalle variabili d'ambiente condivise
# Le variabili sono create dopo il linking dei servizi Cloud Foundry e Cloudant
if 'VCAP_SERVICES' in os.environ:
	vcapServicesData = json.loads(os.environ['VCAP_SERVICES'])

	serviceUsername = vcapServicesData['cloudantNoSQLDB'][0]['credentials']['username']
	servicePassword = vcapServicesData['cloudantNoSQLDB'][0]['credentials']['password']
	serviceURL = vcapServicesData['cloudantNoSQLDB'][0]['credentials']['url']
else:
	serviceUsername = "PUT_YOUR_USERNAME"
	servicePassword = "PUT_YOUR_PASSWORD"
	serviceURL = "PUT_YOUR_URL"

# connessione Cloudant
client = Cloudant(serviceUsername, servicePassword, url=serviceURL)
salt = "puqrnw"
# chiave crittografica
key = base64.b64encode(bytes('T0evLckYUBJ2NWatzp69J3M7EOWovs8i', 'utf-8'))
print(key)

app = flask.Flask(__name__, static_url_path='/assets')

def encrypt(string):
	string = string.encode()
	f = Fernet(key)
	encrypted = f.encrypt(string)

	return encrypted.decode("utf-8")

def decrypt(string):
	f = Fernet(key)
	decrypted = f.decrypt(string.encode())

	return decrypted.decode("utf-8")

def dbSearch(username, service, company, environment):

	client.connect()

	db = client['credentials']

	if username == "" and service == "" and company == "" and environment != "":
		#ricerca solo per ambiente
		res = db.get_query_result(selector={"environment": environment}, raw_result=True)['docs']
	elif username == "" and service == "" and company != "" and environment == "":
		#ricerca solo per azienda
		res = db.get_query_result(selector={"company": company}, raw_result=True)['docs']
	elif username == "" and service == "" and company != "" and environment != "":
		#ricerca per azienda e ambiente
		res =db.get_query_result(selector={"company": company, "environment": environment}, raw_result=True)['docs']
	elif username == "" and service != "" and company == "" and environment == "":
		#ricerca solo per servizio
		res = db.get_query_result(selector={"service": service}, raw_result=True)['docs']
	elif username == "" and service != "" and company == "" and environment != "":
		#ricerca per servizio e ambiente
		res = db.get_query_result(selector={"service" : service, "environment": environment}, raw_result=True)['docs']
	elif username == "" and service != "" and company != "" and environment == "":
		#ricerca per servizio e azienda
		res = db.get_query_result(selector={"service": service, "company": company}, raw_result=True)['docs']
	elif username == "" and service != "" and company != "" and environment != "":
		#ricerca per servizio, azienda e ambiente
		res = db.get_query_result(selector={"service": service, "company": company, "environment": environment}, raw_result=True)['docs']
	elif username != "" and service == "" and company == "" and environment == "":
		#ricerca solo per username
		res = db.get_query_result(selector={"username": username}, raw_result=True)['docs']
	elif username != "" and service == "" and company == "" and environment != "":
		#ricerca per username e ambiente
		res = db.get_query_result(selector={"username": username, "environment": environment}, raw_result=True)['docs']
	elif username != "" and service == "" and company != "" and environment == "":
		#ricerca per username e azienda
		res = db.get_query_result(selector={"username": username, "company": company}, raw_result=True)['docs']
	elif username != "" and service == "" and company != "" and environment != "":
		#ricerca per username, azienda e ambiente
		res = db.get_query_result(selector={"username": username, "company": company, "environment": environment}, raw_result=True)['docs']
	elif username != "" and service != "" and company == "" and environment == "":
		#ricerca per username e servizio
		res = db.get_query_result(selector={"username": username, "service": service}, raw_result=True)['docs']
	elif username != "" and service != "" and company == "" and environment != "":
		#ricerca per username, servizio e ambiente
		res = db.get_query_result(selector={"username": username, "service": service, "environment": environment}, raw_result=True)['docs']
	elif username != "" and service != "" and company != "" and environment == "":
		#ricerca per username, servizio e azienda
		res = db.get_query_result(selector={"username": username, "service": service, "company": company}, raw_result=True)['docs']
	elif username != "" and service != "" and company != "" and environment != "":
		#ricerca per username, servizio, azienda e ambiente
		res = db.get_query_result(selector={"username": username, "service": service, "company": company, "environment": environment}, raw_result=True)['docs']
	else:
		#ricerca tutti i dati
		res = []
		for doc in db:
			res.append(doc)

	for doc in res:
		doc["password"] = decrypt(doc["password"])

	client.disconnect()

	return res

def dbAdd(username, password, service, company, url, environment, timestamp, comment):

	client.connect()

	db = client['credentials']
	doc = db.create_document({"username": username, "password": password, "service": service, "company": company, "url": url, "environment": environment, "timestamp": timestamp, "comment": comment})

	client.disconnect()

	return doc

def dbUpdate(obj_id, password, service, company, url, environment, new_timestamp, comment):

	client.connect()

	db = client['credentials']
	doc = db[obj_id]

	doc['password'] = password
	doc['service'] = service
	doc['company'] = company
	doc['url'] = url
	doc['environment'] = environment
	doc['timestamp'] = new_timestamp
	doc['comment'] = comment
	doc.save()

	client.disconnect()

	return doc

def dbDelete(obj_id):

	client.connect()

	db = client['credentials']
	doc = db[obj_id]
	doc.delete()

	client.disconnect()

	return doc

def dbLogin(username, password):
	
	client.connect()

	db = client['users']
	res = db.get_query_result(selector={"username": username, "password": password}, raw_result=True)['docs']
	hash = ''
	if len(res) != 0:
		hash = hashlib.sha512((str(datetime.now().hour) + salt).encode()).hexdigest()[:20]

	client.disconnect()

	return hash

@app.route('/')
def index():
	return flask.render_template('login.html')

@app.route('/index.html')
def home():
	return flask.render_template('index.html')

@app.route('/login.html')
def login():
	return flask.render_template('login.html')

@app.route('/information.html')
def info():
	return flask.render_template('information.html')

@app.route('/search_key.html')
def search():
	return flask.render_template('search_key.html')

@app.route('/', methods=['POST'])
def home_login_post():
	
	username = request.form['username']
	password = request.form['password']

	token = dbLogin(username, password)[:20]

	if token != '':
		session["token"] = token
	
		return redirect(url_for('home'))
	else:
		error_msg = "Credenziali errate! Riprova ad effettuare l'autenticazione"

		return flask.render_template('login.html', error=error_msg)

@app.route('/login.html', methods=['POST'])
def login_post():
	
	username = request.form['username']
	password = request.form['password']

	token = dbLogin(username, password)[:20]

	if token != '':
		session["token"] = token
	
		return redirect(url_for('home'))
	else:
		error_msg = "Credenziali errate! Riprova ad effettuare l'autenticazione"

		return flask.render_template('login.html', error=error_msg)

@app.route('/search_key.html', methods=['POST'])
def search_post():

	if session.get('token') is not None:
		token = session["token"]
	else:
		token = ""
	
	checkToken = hashlib.sha512((str(datetime.now().hour) + salt).encode()).hexdigest()[:20]

	if token == checkToken:

		username = request.form['username'].upper()
		service = request.form['service'].upper()
		company = request.form['company'].upper()
		environment = request.form['environment'].upper()

		title = "Risultati della ricerca"
		back_url = "search_key.html"

		res = dbSearch(username, service, company, environment)

		if len(res) != 0:
			return flask.render_template('confirmation.html', data=res, title=title, back_url=back_url)
		else:
			return flask.render_template('blank.html', data=res, title=title, back_url=back_url)

	else:
		return redirect(url_for('login'))

@app.route('/update_key.html')
def update():
	return flask.render_template('update_key.html')

@app.route('/update_key.html', methods=['POST'])
def update_post():

	if session.get('token') is not None:
		token = session["token"]
	else:
		token = ""
	
	checkToken = hashlib.sha512((str(datetime.now().hour) + salt).encode()).hexdigest()[:20]

	if token == checkToken:

		action = request.form['action']

		username = request.form['username'].upper()
		service = request.form['service'].upper()
		company = request.form['company'].upper()
		environment = request.form['environment'].upper()

		title = "Aggiorna credenziali"
		back_url = "update_key.html"
		scope = "Aggiorna"
		mode = ""

		if action == "Cerca":

			res = dbSearch(username, service, company, environment)

			if len(res) != 0:
				return flask.render_template('change.html', data=res, title=title, back_url=back_url, scope=scope, mode=mode)
			else:
				return flask.render_template('blank.html', data=res, title=title, back_url=back_url)

		elif action == "Aggiorna":

			password = request.form['password']
			enc_psw = encrypt(password)
			url = request.form['url']
			environment = request.form['environment'].upper()
			obj_id = request.form['obj_id']
			comment = request.form['comment']
			
			new_timestamp = datetime.now(pytz.timezone('Europe/Berlin')).strftime("%d-%m-%Y %H:%M:%S")

			res = [dbUpdate(obj_id, enc_psw, service, company, url, environment, new_timestamp, comment)]
			res[0]["password"] = password

			if len(res) != 0:
				return flask.render_template('confirmation.html', data=res, title=title, back_url=back_url, scope=scope, mode=mode)
			else:
				return flask.render_template('blank.html', data=res, title=title, back_url=back_url)
	else:
		return redirect(url_for('login'))

@app.route('/create_key.html')
def create():
	return flask.render_template('create_key.html')

@app.route('/create_key.html', methods=['POST'])
def create_post():

	if session.get('token') is not None:
		token = session["token"]
	else:
		token = ""
	
	checkToken = hashlib.sha512((str(datetime.now().hour) + salt).encode()).hexdigest()[:20]

	if token == checkToken:

		username = request.form['username'].upper()
		password = request.form['password']
		enc_psw = encrypt(password)
		service = request.form['service'].upper()
		company = request.form['company'].upper()
		url = request.form['url']
		environment = request.form['environment'].upper()
		timestamp = datetime.now(pytz.timezone('Europe/Berlin')).strftime("%d-%m-%Y %H:%M:%S")
		comment = request.form['comment']

		title = "Dati inseriti correttamente"
		back_url = "create_key.html"

		res = [dbAdd(username, enc_psw, service, company, url, environment, timestamp, comment)]
		res[0]["password"] = password

		return flask.render_template('confirmation.html', data=res, title=title, back_url=back_url)
	else:
		return redirect(url_for('login'))

@app.route('/delete_key.html')
def delete():
	return flask.render_template('delete_key.html')

@app.route('/delete_key.html', methods=['POST'])
def delete_post():

	if session.get('token') is not None:
		token = session["token"]
	else:
		token = ""
	
	checkToken = hashlib.sha512((str(datetime.now().hour) + salt).encode()).hexdigest()[:20]

	if token == checkToken:

		action = request.form['action']

		username = request.form['username'].upper()
		service = request.form['service'].upper()
		company = request.form['company'].upper()
		environment = request.form['environment'].upper()

		title = "Cancella credenziali"
		back_url = "delete_key.html"
		scope = "Cancella"
		mode = "readonly"

		if action == "Cerca":
			
			res = dbSearch(username, service, company, environment)

			session["query_username"] = username
			session["query_service"] = service
			session["query_company"] = company
			session["query_environment"] = environment

			if len(res) != 0:
				return flask.render_template('change.html', data=res, title=title, back_url=back_url, scope=scope, mode=mode)
			else:
				return flask.render_template('blank.html', data=res, title=title, back_url=back_url)

		elif action == "Cancella":
			
			obj_id = request.form['obj_id']

			dbDelete(obj_id)
			res = dbSearch(session["query_username"], session["query_service"], session["query_company"], session["query_environment"])

			if len(res) != 0:
				return flask.render_template('change.html', data=res, title=title, back_url=back_url, scope=scope, mode=mode)
			else:
				return flask.render_template('blank.html', data=res, title=title, back_url=back_url)
	else:
		return redirect(url_for('login'))

app.secret_key = "pinguinotto"
port = int(os.getenv('PORT', '5000'))

if __name__ == "__main__":
	app.run(host='0.0.0.0', port=int(port))