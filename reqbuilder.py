#!/usr/bin/python
#coding:utf-8

import urllib, urllib2, os, time, gzip
from scapy.all import *

count = 0
requests = []

def execute(cmd): return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()

def find_host(request) :
	try :
		return re.compile('Host: (.*)').findall(request)[0].strip()
	except :
		return ""
		pass

def find_method(request) :
	try :
		return re.compile('(^[^\ ]*\ )').findall(request)[0].strip()
	except :
		return ""
		pass
def find_uri(request) :
	try :
		return re.compile('(\ [^\ ]*\ )').findall(request)[0].strip()
	except :
		return ""
		pass

def list_requests(requests) :
	i = 0
	for request in requests :
		i += 1
		print str(i)+" "+find_method(request)+" "+find_host(request)+find_uri(request)

def replay(request) :
	url = "http://"+find_host(request)+find_uri(request)
	new_request = urllib2.Request(url)
	
	post = 0
	
	for line in request.split('\n') :
		if ":" in line :
			splited = line.strip().split(":", 1)
			if "Host" not in splited[0]:
				new_request.add_header(splited[0].strip(), splited[1].strip())
		elif post :
			data = line
		else :
			if line.strip() == "" and find_method(request) == "POST" :
				post = 1
	try : 
		if post : reply = urllib2.urlopen(new_request,data)
		else : reply = urllib2.urlopen(new_request)
	
		filename_base = re.compile('(.*)\.[^\.]*').findall(find_host(request))[0].strip()
		filename = filename_base
		i = 0
		while os.path.isfile(filename) :
			i+=1
			filename=filename_base+str(i)
		
		newfile = open(filename,"w")
		newfile.write(reply.read())
		newfile.close()
	
		print filename+" enregistré avec succès."
		
		typefile = execute("file "+filename)
		
		print "File : "+typefile+"\n"
		
		if "gzip" in typefile :
			choice = raw_input("uncompress ? (o/n)")
			if "o" in choice :
				newfile = open(filename+"_uncompress","w")
				newfile_gz = gzip.open(filename, 'rb')
				newfile.write(newfile_gz.read())
				newfile_gz.close()
				newfile.close()
	
			print filename+"_uncompress enregistré avec succès."
	except :
		print "Erreur HTTP"
		pass

	menu(request)

def export(request) :
	url = "http://"+find_host(request)+find_uri(request)
	
	filename_base = "request_"+re.compile('(.*)\.[^\.]*').findall(find_host(request))[0].strip().replace("www.","")+".py"
	filename = filename_base
	i = 0
	while os.path.isfile(filename) :
		i+=1
		filename=str(i)+filename_base
		
	newfile = open(filename,"w")
	newfile.writelines([
	'#!/usr/bin/python\n',
	'#coding:utf-8\n\n',
	'import urllib, urllib2\n\n',
	'request = urllib2.Request("'+url+'")\n\n',
	])
	
	post = 0
	
	for line in request.split('\n') :
		if ":" in line :
			splited = line.strip().split(":", 1)
			if "Host" not in splited[0]:
				newfile.write('request.add_header("'+splited[0].strip()+'", "'+splited[1].strip().replace('"','')+'")\n')
		elif post :
			data = line
		else :
			if line.strip() == "" and find_method(request) == "POST" :
				post = 1
				
	if post : newfile.write('\nreply = urllib2.urlopen(request,"'+data.strip()+'")\n')
	else : newfile.write('\nreply = urllib2.urlopen(request)\n')
	newfile.write('\nprint reply.read()\n\n')
	newfile.close()

	print filename+" créé."

	menu(request)

def select() :
	global requests
	os.system("clear")
	print "------------------------------------------------------------"
	list_requests(requests)
	print  "------------------------------------------------------------"
	req = raw_input('Sélectionner la requête : ')
	request = requests[int(req)-1]
	print "------------------------------------------------------------"
	print request
	menu(request)
	

def menu(request) :
	print "------------------------------------------------------------"
	print """
		--- Request Builder ---

	[+] 1 - Relancer la capture
	[+] 2 - Sélectionner une autre requête
	[+] 3 - Rejouer la requête et enregistrer le résultat
	[+] 4 - Exporter la requête en python
	[+] 5 - Quitter
	"""	
	choix = raw_input("Sélection : ")
	print
	if choix > "4":
		exit()
	else :		
		if choix == "1": 
			main()		
		elif choix == "2": 
			select()
		elif choix == "3":
			replay(request)
		elif choix == "4":
			export(request)

def handle(p) :
	paquet  = p[Raw].load
	if "HTTP" in paquet :
		global count, requests
		count += 1
		print str(count)+" "+find_method(paquet)+" http://"+find_host(paquet)+find_uri(paquet)
		requests.append(paquet)

def main() :
	try :
		global requests
		requests = []
		print "Sniffing HTTP"
		n = input("Nombre de paquets HTTP à capturer :")
		sniff( count = n, store = 0, filter = "tcp and dst port 80", lfilter = lambda(p): p.haslayer(TCP) and p.haslayer(Raw), prn = handle )
		select()
	except (KeyboardInterrupt):
		select()

main()
