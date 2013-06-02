#!/usr/bin/python
#coding:utf-8

import urllib, urllib2, os, time, gzip
from scapy.all import *

dashs = "-"*80

http_timeout = 5

count = 0
requests = []

def execute(cmd) : return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()

def clear() :
	os.system("clear")
	print dashs

def find_host(request) :
	try :
		return re.compile('Host: (.*)').findall(request)[0].strip()
	except :
		return ""
		pass

def find_method(request) :
	try :
		return re.compile('^([^\ ]+\ )').findall(request)[0].strip()
	except :
		return ""
		pass
		
def find_uri(request) :
	try :
		return re.compile('(\ [^\ ]+\ )').findall(request)[0].strip()
	except :
		return ""
		pass

def find_postdata(request) :
	try :
		lines = request.replace("\r","\n").replace("\n\n","\n").split("\n")

		i = 0

		while i < len(lines) :
			if lines[i].strip() == "" :
				return lines[i+1]
				break
			i += 1
	except :
		return ""
		pass

def find_contentlength(request) :
	try :
		return re.compile('Content-Length: ([0-9]+)').findall(request)[0].strip()
	except :
		return ""
		pass

def list_requests(requests) :
	i = 0
	for request in requests :
		i += 1
		print str(i)+" "+find_method(request)+" http://"+find_host(request)+find_uri(request)

def give_filename(filename,ext) :
	basename = filename.replace("www.","")
	tmp = basename
	i = 0
	while os.path.isfile(tmp+"."+ext) :
		i+=1
		tmp=basename+str(i)
	return tmp+"."+ext

def play(request,save) :
	url = "http://"+find_host(request)+find_uri(request)
	new_request = urllib2.Request(url)

	lines = request.replace("\r","\n").replace("\n\n","\n").split("\n")

	i = 0

	while i < len(lines) :
		if i == 0 :
			if find_method(lines[i]) == "POST" :
				post = 1
			else :
				post = 0
		elif post and lines[i].strip() == "" :
			data = lines[i+1]
			break
		elif lines[i].strip() != "" :
			splited = lines[i].strip().split(":", 1)
			if "Host" not in splited[0] :
				new_request.add_header(splited[0].strip(), splited[1].strip())
		i += 1
	
	print "Sending request..."
	
	out = ""	

	try :
		if post : reply = urllib2.urlopen(new_request,data,timeout = http_timeout)
		else : reply = urllib2.urlopen(new_request,timeout = http_timeout)
		clear()
		print "Reply : "
		print dashs
		print "HTTP status : "+str(reply.getcode())
		print reply.info()
		if save :
			out = reply.read()
			
	except urllib2.HTTPError, e :
		print "Error HTTP, code : ", e.code
		if e.code == 304 :
			lines = ""
			for line in request.replace("\r","\n").replace("\n\n","\n").split("\n") :
				if "If-Modified-Since: " in line :
					lines += "\n  "+line
					break
			for line in request.replace("\r","\n").replace("\n\n","\n").split("\n") :
				if "If-None-Match: " in line :
					lines += "\n  "+line
					break
			if lines : print "Remove these lines in the request to disable last modification detection : "+lines
	except urllib2.URLError, e :
		print "Can't reach a server."
		print "Reason: ", e.reason
	except socket.timeout, e:
		print "Timeout."
	
	if out :
		filename = give_filename(re.compile('(.*)\.[^\.]*').findall(find_host(request))[0].strip(),"out")

		newfile = open(filename,"w")
		newfile.write(out)
		newfile.close()

		typefile = execute("file "+filename)

		print dashs
		print "File "+filename+" saved.\n"+typefile

		if "gzip" in typefile :
			for line in request.replace("\r","\n").replace("\n\n","\n").split("\n") :
				if "Accept-Encoding: " in line :
					print "Remove this line in the request to disable gzip compression : \n  "+line
					break
			choice = raw_input("\nDecompress gzip now (y/n) ? ")
			if "y" in choice :				
				newfile = gzip.open(filename,"rb")
				out = newfile.read()
				newfile.close()
				newfile = open(filename,"w")
				newfile.write(out)
				newfile.close()
				typefile = execute("file "+filename)
				print "\nFile "+filename+" saved.\n"+typefile

	print dashs
	menu_handling(request)

def export_raw(request) :
	filename = give_filename("newreq_"+re.compile('(.*)\.[^\.]*').findall(find_host(request))[0].strip(),"raw")
	newfile = open(filename,"w")
	newfile.write(request)
	newfile.close()
	
	clear()
	print "File "+filename+" saved."
	print dashs
	menu_export(request)

def export_python(request) :
	url = "http://"+find_host(request)+find_uri(request)
	
	filename = give_filename("newreq_"+re.compile('(.*)\.[^\.]*').findall(find_host(request))[0].strip(),"py")

	newfile = open(filename,"w")
	newfile.writelines([
	'#!/usr/bin/python\n',
	'#coding:utf-8\n\n',
	'import urllib, urllib2\n\n',
	'request = urllib2.Request("'+url+'")\n\n'
	])

	lines = request.replace("\r","\n").replace("\n\n","\n").split("\n")

	i = 0

	while i < len(lines) :

		if i == 0 :
			if find_method(lines[i]) == "POST" :
				post = 1
			else :
				post = 0
		elif post and lines[i].strip() == "" :
			data = lines[i+1]
			break
		elif lines[i].strip() != "" :
			splited = lines[i].strip().split(":", 1)
			if "Host" not in splited[0]:
				newfile.write('request.add_header("'+splited[0].strip()+'", "'+splited[1].strip().replace('"','')+'")\n')
		i += 1

	if post : newfile.write('\nreply = urllib2.urlopen(request,"'+data.strip()+'",timeout = '+str(http_timeout)+')\n')
	else : newfile.write('\nreply = urllib2.urlopen(request,timeout = '+str(http_timeout)+')\n')
	newfile.write('\nprint reply.read()\n\n')
	newfile.close()
	clear()
	print "File "+filename+" saved."
	print dashs
	menu_export(request)
	
def export_bash(request) :
	url = "http://"+find_host(request)+find_uri(request)
	
	filename = give_filename("newreq_"+re.compile('(.*)\.[^\.]*').findall(find_host(request))[0].strip(),"sh")

	wget = "wget "	

	lines = request.replace("\r","\n").replace("\n\n","\n").split("\n")

	i = 0

	while i < len(lines) :

		if i == 0 :
			if find_method(lines[i]) == "POST" :
				post = 1
			else :
				post = 0
		elif post and lines[i].strip() == "" :
			data = lines[i+1]
			break
		elif lines[i].strip() != "" :
			splited = lines[i].strip().split(":", 1)
			if "Host" not in splited[0] :
				wget += "--header='"+splited[0].strip()+": "+splited[1].strip()+"' "
		i += 1

	if post : wget += "--post-data='"+data.strip()+"' "
	
	wget += url
	
	newfile = open(filename,"w")
	newfile.writelines(['#!/bin/bash\n\n',wget+'\n'])
	newfile.close()
	clear()
	print "File "+filename+" saved."
	print dashs
	menu_export(request)

def modify(request) :
	if find_method(request) == "POST" :
		data = find_postdata(request)
		post = 1
	else : 
		post = 0

	newfile = open("reqbuilder.tmp","w")
	newfile.write(request)
	newfile.close()
	os.system("nano reqbuilder.tmp")
	newfile = open("reqbuilder.tmp","r")
	newrequest = newfile.read()
	newfile.close()
	os.system("rm reqbuilder.tmp")
	
	clear()
	
	if newrequest in request :
		print "Nothing changed.\n"+dashs
		print request
	else : 
		request = newrequest
		print "Modifications applied.\n"+dashs
		print request
		newdata = find_postdata(request)
		if post and data != newdata :
			old_data_length = int(find_contentlength(request))
			new_data_length = len(newdata)
			if new_data_length != old_data_length :
				print "Post data length's has changed, you should update the header : 'Content-length'."
				choice = raw_input("Update 'Content-Length: "+str(old_data_length)+"' to 'Content-Length: "+str(new_data_length)+"' (y/n) ? ")
				if "y" in choice :	
					request = request.replace("Content-Length: "+str(old_data_length),"Content-Length: "+str(new_data_length))
					
					clear()
					print "Modifications applied.\n"+dashs
					print request
	
	print dashs				
	menu_handling(request)

def select() :
	global requests
	if len(requests) == 0 :
		clear()
		print "No request found ..."
		print dashs
		menu_import()
	else :
		clear()
		list_requests(requests)
		print dashs
		req = raw_input('Select a request : ')
		request = requests[int(req)-1]
		clear()
		print request
		print dashs
		menu_handling(request)

def pcap() :
	global requests, count
	
	path = ""
	while not os.path.isfile(path) :
		if path : print "No such file"
		path = raw_input("Path of the pcap file : ")
	
	count = 0
	requests = []
		
	print "Loading "+path+" ..."
	
	packets = rdpcap(path)
    
	for packet in packets :
		if check(packet) :
			handling(packet)
	print
	select()

def import_raw() :
	path = ""
	while not os.path.isfile(path) :
		if path : print "No such file"
		path = raw_input("Path of the raw file : ")
	
	rawfile = open(path,"r")
	request = rawfile.read()
	rawfile.close()
	
	clear()
	print request
	print dashs
	menu_handling(request)

def display(request) :
	clear()
	print request
	print dashs
	menu_handling(request)

def menu_handling(request) :
	print """
		--- Request Builder | Handling ---

	[+] 1 - Display the current request
	[+] 2 - Modify the current request
	[+] 3 - Play the current request
	[+] 4 - Play the current request and save the result
	[+] 5 - Export the current request
	[+] 6 - Back to import
	[+] 0 - Exit
	"""	
	while 1 :
		choice = raw_input("Choice ( or sh command ) : ")
		if choice :
			if len(choice) == 1 and choice.isdigit() :
				choice = int(choice)
				if   choice <  1 : exit()
				elif choice == 1 : display(request)
				elif choice == 2 : modify(request)
				elif choice == 3 : play(request,0)
				elif choice == 4 : play(request,1)
				elif choice == 5 : clear(); menu_export(request)
				elif choice == 6 : clear(); menu_import()
				else :
					clear()
					menu_handling(request)
			else :
				print
				print execute(choice)
		else :
			clear()
			menu_handling(request)

def menu_export(request) :
	print request
	print dashs
	print """
		--- Request Builder | Export ---

	[+] 1 - Export in raw format
	[+] 2 - Export in a python script
	[+] 3 - Export in a bash script	
	[+] 0 - Back	
	"""	
	while 1 :
		choice = raw_input("Choice ( or sh command ) : ")
		if choice :
			if len(choice) == 1 and choice.isdigit() :
				choice = int(choice)
				print
				if   choice <  1 : clear(); menu_handling(request)
				elif choice == 1 : export_raw(request)
				elif choice == 2 : export_python(request)
				elif choice == 3 : export_bash(request)
				else :
					clear()
					menu_export(request)
			else :
				print
				print execute(choice)
		else :
			clear()
			menu_export(request)

def menu_import() :
	print """
		--- Request Builder | import ---

	[+] 1 - Sniff the network
	[+] 2 - Open a pcap file
	[+] 3 - Open a raw request
	[+] 0 - Exit
	"""	
	while 1 :
		choice = raw_input("Choice ( or sh command ) : ")
		if choice :
			if len(choice) == 1 and choice.isdigit() :
				choice = int(choice)
				print
				if   choice <  1 : exit()
				elif choice == 1 : sniff_tcp()
				elif choice == 2 : pcap()
				elif choice == 3 : import_raw()
				else :
					clear()
					menu_import()
			else :
				print
				print execute(choice)
		else :
			clear()
			menu_import()
	
def handling(p) :
	packet  = p[Raw].load
	global count, requests
	count += 1
	print str(count)+" "+find_method(packet)+" http://"+find_host(packet)+find_uri(packet)
	requests.append(packet)

def check(p) :
	if p.haslayer(TCP) and p.haslayer(Raw) :
		try :
			if any( find_method(p[Raw].load) == test for test in ["GET","HEAD","POST","OPTIONS","CONNECT","TRACE","PUT","PATCH","DELETE"] ) :
				return p
		except :
			pass

def sniff_tcp() :
	try :
		global requests, count
		count = 0
		requests = []
		n = ""
		while not ( n and n.isdigit() ) : n = raw_input("Number of requests to sniff ( 0 = unlimited ) : ")
		n = int(n)
		clear()
		sniff( count = n, store = 0, filter = "tcp", lfilter = check, prn = handling )
		select()
	except (KeyboardInterrupt) :
		select()

clear()
menu_import()

"""
newxhr = new XMLHttpRequest();
newxhr.open( "GET", "dginio.fr", false );
newxhr.setRequestHeader('Connection', 'keep-alive');
newxhr.setRequestHeader('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
newxhr.setRequestHeader('Origin', 'http://www.commentcamarche.net');
newxhr.setRequestHeader('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.52 Safari/537.17');
newxhr.setRequestHeader('Referer', 'http://www.commentcamarche.net/');
newxhr.setRequestHeader('Accept-Language', 'fr-FR,fr;q=0.8,en-US;q=0.6,en;q=0.4');
newxhr.setRequestHeader('Accept-Charset', 'ISO-8859-1,utf-8;q=0.7,*;q=0.3');
newxhr.send( null );
console.log(newxhr.responseText);
"""
