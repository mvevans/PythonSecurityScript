#Chrome Program for windows 
#IDS.py [interval of check in seconds]
#IDS.py 5

import sys
import os
import re
import time


def writearray(array, file):
	for str in array:
		if str not in ('TCP','UDP'):
			file.write(', ')
		file.write(str)
	file.write('\n')

#BLACKLISTs
BLACKLIST_PORTS = [23,135,5,7,18,20,21,22,69,70,79,103,108,109,115,119,161,139,190,197,396,444,458,563,569,1080]
BLACKLIST_PRGMS = ['cmd','notepad']
BLACKLIST_IPS = []

#WHITELISTs
WHITELIST_PORTS = []
WHITELIST_SHARES = []

#Build base file
os.system('netstat -naob > stat.txt')
interval = sys.argv[1]

#Friendly IPs
WHITELIST_IPs = ['172.16.254','192.168.23']


#open log
logfile = open('log.txt','w')

#TODO:add log info about blacklists
#TODO: add more options for how program is to run
#TODO:add check for closed ports and killed pids

#configure users
print 'configure user time!'
os.system('net user > user.txt')
userfile = open('user.txt','r')

users = []
userlist = []
line = userfile.readline();
while not(r'---' in line):
	line = userfile.readline();

line = userfile.readline()
while 'The command completed successfully.' not in line:
	lina = re.split('\s+',line)
	while lina.count('') > 0:
		lina.remove('')
	users.extend(lina)	
	line = userfile.readline()
userfile.close()

print "adding active status to users"
for user in users:
	usas = [user]
	if user in 'Guest':
		usas.append('No')
	else:
		usercommand = ('net user '+user+' > user.txt')
		os.system(usercommand)
		iuserfile = open('user.txt','r')
		line = iuserfile.readline()
		while 'Account active' not in line:
			line = iuserfile.readline()
		matchobj = re.search('\s+(?P<act>\w+)$',line)
		usas.append(matchobj.group('act'))
		iuserfile.close()
	userlist.append(usas)
	

print 'configure ports time!'
#configure ports

initfile = open('stat.txt','r')
initfile.readline();
initfile.readline();
initfile.readline();
initfile.readline();
i = 0
lines = []
linen = []
for line in initfile.readlines():
	lina = re.split('\s+',line)
	lina.pop(0)
	if lina.count('') > 0:
		lina.remove('')
	if (lina.count('Can') > 0)  and (lina.count('not') > 0):
		a = lina.index('Can')
		lina.pop(a);
		lina.pop(a);
		lina.pop(a);
		lina.pop(a);
		lina.pop(a);
		lina.insert(a,'[PROGRAM UNKNOWN]')
	if lina[0] in ('TCP','UDP'):
		if len(linen) >= 1:
			lines.append(linen)
			linen = []
		linen.extend(lina)
	else:
		linen.extend(lina)
	

initfile.close();
testfile = open('test.txt','w')
testfile.write('Protocol, Local Address, Foreign Address, State, PID, Program\n')

#Create OK List
PIDs = []
nPIDs = []
nPORTs = []
openports= []
for line in lines:
	writearray(line,testfile)
	matchobj = re.search('(?P<port>\d+)$',line[1])
	openports.append(matchobj.group('port'))
	if len(line) >= 5:
		PIDs.append(line[4])
testfile.close()

print openports
#TODO:add log entry about current open ports

#The Beef

os.system('reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f')
os.system('reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f')

while(1):
	os.system('netstat -naob > stat.txt')

	initfile = open('stat.txt','r')
	initfile.readline();
	initfile.readline();
	initfile.readline();
	initfile.readline();
	i = 0
	lines = []
	linen = []
	for line in initfile.readlines():
		lina = re.split('\s+',line)
		lina.pop(0)
		if lina.count('') > 0:
			lina.remove('')
		if (lina.count('Can') > 0)  and (lina.count('not') > 0):
			a = lina.index('Can')
			lina.pop(a);
			lina.pop(a);
			lina.pop(a);
			lina.pop(a);
			lina.pop(a);
			lina.insert(a,'[PROGRAM UNKNOWN]')
		if lina[0] in ('TCP','UDP'):
			if len(linen) >= 1:
				lines.append(linen)
				linen = []
			linen.extend(lina)
		else:
			linen.extend(lina)
	initfile.close();
	for line in lines:
			
		#************CHECK NETWORK*********
			
		#Check for new Connections (Report only)
		if len(line) >= 5:
			newflag = 1
			for pid in PIDs:
				if pid == line[4]:
					newflag = 0
			for pid in nPIDs:
				if pid == line[4]:
					newflag = 0
			if newflag == 1:
				print 'New connection!\n'
				print 'Information: ', line,'\n\n'
				nPIDs.append(line[4])
				#TODO:Add log entry with info and timestamp
		
		#Check Ports
		matchobj = re.search('(?P<port>\d+)$',line[1])
		if (openports.count(matchobj.group('port')) == 0) and (WHITELIST_PORTS.count(matchobj.group('port')) == 0):
			if nPIDs.count(matchobj.group('port')) == 0:
				print 'Port ',matchobj.group('port'),' has been opened.\n'
				print 'Information: ', line,'\n'
				nPIDs.append(matchobj.group('port'))
				#killcmd = ('Taskkill /PID '+line[4]+' /F')
				#os.system(killcmd)
				#TODO:Add log entry with info and timestamp
		
		if BLACKLIST_PORTS.count(matchobj.group('port')) > 0:				#****************might add ip address to a blacklist,add firewall rule
			print 'Blacklisted Port ',matchobj.group('port'),' is open. Closing\n'
			print 'Information: ', line,'\n\n'
			killcmd = str('Taskkill /PID '+line[4]+' /F')
			os.system(killcmd)
			#TODO:Add log entry with info and timestamp
		
		#Check Programs
		for pgrms in BLACKLIST_PRGMS:
			if len(line) >= 6:
				if pgrms.lower() in line[5].lower():
					print 'BLACKLIST_PROGRAM ',pgrms,' DETECTED. Closing\n'
					print 'Information: ', line,'\n\n'
					killcmd = ('Taskkill /PID '+line[4]+' /F')
					os.system(killcmd)
					
					if not(('*:*' in line[2]) or ('::' in line[2])):
						matchobj = re.search('^(?P<ip>\d+[.]\d+[.]\d+[.]\d+)',line[2])
						try:
						  matchobj.group(ip)
						except NameError:
						  print "IPv6 or other non standard ip address"
						else:
							pivotflag = 1
							for ip in WHITELIST_IPs:
								if ip in matchobj.group('ip'):	#pivot from a friendly
									print "PIVOT DETECTED: ",matchobj.group('ip')
									pivotflag = 0
							if pivotflag:
								print "Blacklisting the attacker with ip: ",matchobj.group('ip')
								BLACKLIST_IPS.append(matchobj.group('ip'))
						#TODO:Add log entry with info and timestamp
		
		#TODO:Check IPs
		if not(('*:*' in line[2]) or ('::' in line[2])):
			matchobj = re.search('(?P<ip>\d+[.]\d+[.]\d+[.]\d+)',line[2])#add protection against ipv6 and no ips
			if matchobj.group('ip') in BLACKLIST_IPS:
				print 'BLACKLISTED IP ',matchobj.group('IP'),' CONNECTION DETECTED. Closing\n'
				print 'Information: ', line,'\n\n'
				killcmd = str('Taskkill /PID '+line[4]+' /F')
				os.system(killcmd)
	

	#************CHECK USERS***************
	#get current user situation
	os.system('net user > user.txt')
	userfile = open('user.txt','r')
	users = []
	line = userfile.readline();
	while not r'---' in line:
		line = userfile.readline();
	line = userfile.readline()
	while 'The command completed successfully.' not in line:
		lina = re.split('\s+',line)
		while lina.count('') > 0:
			lina.remove('')
		users.extend(lina)	
		line = userfile.readline()
	userfile.close()
	nuserlist = []
	for user in users:
		usas = [user]
		usercommand = ('net user '+user+' > user.txt')
		os.system(usercommand)
		iuserfile = open('user.txt','r')
		line = iuserfile.readline()
		while 'Account active' not in line:
			line = iuserfile.readline()
		matchobj = re.search('\s+(?P<act>\w+)$',line)
		usas.append(matchobj.group('act'))
		iuserfile.close()
		nuserlist.append(usas)
		
	#Compare with desired
	for nuser in nuserlist:
		userflag = 1
		actflag = 1
		for user in userlist:
			if nuser[0] in user[0]:#valid user
				userflag = 0
				if nuser[1] in user[1]:#good active state
					actflag = 0
		if userflag:
			print 'UNAUTHORIZED USER ACCOUNT: ',nuser[0],'. Deleting user.'
			userkill = ('net user /delete '+nuser[0])
			os.system(userkill)
			
		if actflag:
			print 'USER ',nuser[0],' HAS AN ACTVE STATUS SET TO ',nuser[1],'. Changing.'
			if nuser[1] in 'Yes':
				nact = 'No'
			else:
				nact = 'Yes'
			useract = ('net user '+nuser[0]+' /active:'+nact)
			os.system(useract)
	
	#Check Shares
	os.system('net share > share.txt')
	shrfile = open('share.txt','r')
	line = shrfile.readline();
	while not r'---' in line:
		line = shrfile.readline();
	line = shrfile.readline()
	shares = []
	while 'The command completed successfully.' not in line:
		lina = re.split('\s+',line)
		while lina.count('') > 0:
			lina.remove('')
		shares.append(lina)	
		line = shrfile.readline()
	shrfile.close()
	
	
	time.sleep(float(interval))