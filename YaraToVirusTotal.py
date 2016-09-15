#Script is still being developed.
import json
import requests
import sys
import os
import time

username = "" #Nessus username
password = "" #Nessus password
url = "https://:8834" #Enter Nessus IP

uploadSite = "https://www.virustotal.com/vtapi/v2/file/scan"
reportSite = "https://www.virustotal.com/vtapi/v2/file/report"

#VirusTotal API key. 
api = ""

#caps a limit of the number of files to download from Nessus
limitFiles = 25

requests.packages.urllib3.disable_warnings()

def getToken():
	token = requests.post(url+"/session", data={"username":username,"password":password},verify=False)
	
	if(token.status_code == 200):
		login = token.json()['token']
		headers = {'X-Cookie':'token='+login, 'Content-Type':'application/json'}
		return(login,headers)
	else:
		print("\n\nExiting.Could not log into Nessus with credentials supplied.\n\n")
		sys.exit()

#downloads the files from the Nessus scanner
def getAttachments(login,headers,scanID):
	counter = 1
	str(scanID)

	output = (url + "/scans/" + scanID + "/plugins/91990")
		
	yaraFiles = requests.get(output, headers=headers,verify=False)
	attachments = yaraFiles.json()['outputs']

#loops through the json to get to the file name, id, and key
	for m in attachments:
		loopJson = m['ports']	
		for n in loopJson['445 / tcp / cifs']:
			#can uncomment if the ip/hostname is needed for the host
			#print(n['hostname'])
			attachments = n['attachments']
			for o in attachments:
				name = o['name']
				id = o['id']
				key = o['key']
				downloadFiles = (url + "/scans/" + scanID + /attachments/" + str(id) + "/?key=" + str(key))
				counter += 1
				with open(name,'wb') as f:
	                        	resp = requests.get(downloadFiles,headers=headers,verify=False)
        	                	f.write(resp.content)
                	        	f.close()
		if(counter > limitFiles):	
			break	

def virusTotal():
	uploadHeader = ({'apikey':api})	
	for filename in os.listdir('./'):
	#time.sleep needed to stay within virustotal api's limits	
		time.sleep(3)
	
		files = {'file':open(filename,'rb')}
		str(files)
		print("Submitting file",filename)
		r = requests.post(uploadSite,files=files,params=uploadHeader)
		#sleep for 15 seconds to wait for the VirusTotal API		
		print(r.status_code)
		time.sleep(15)

		resource = r.json()["resource"]

		parameters = ({"resource":resource,"apikey":api})
		print("Requesting report for: ",filename)
		time.sleep(15)
		f = requests.post(reportSite,parameters)
		print(f.status_code)
		print(f.text)

		msg = f.json()["verbose_msg"]

		if(f.status_code == 200 and msg == "Scan finished, information embedded"):
			total = f.json()["positives"]	
			print("The file name ", filename, "matched: ",total)
		else:
			print("Waiting additional time for VirusTotal")
			time.sleep(30)
			f = requests.post(reportSite,parameters)
			print(f.status_code)
			total = f.json()["positives"]
			print("The file name ", filename, " matched: ", total)
		
if __name__ == '__main__':
	login,headers = getToken()
	scanID = input("What is the ID of the scan? ")
	getAttachments(login,headers,scanID)
	
	virusTotal()
