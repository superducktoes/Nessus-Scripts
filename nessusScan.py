import json
import requests
import sys #used for command line arguments

#replace these with the keys for the account used for scanning
accessKey = ""
secretKey = ""

url = "https://cloud.tenable.com/"
headers = {'X-ApiKeys': 'accessKey=' + str(accessKey) + '; secretKey = ' + str(secretKey) + ';'}

#gets a list of available policies
def listPolicies():
	policies = requests.get(url+"policies/",headers=headers,verify=True)
	listPolicies = policies.json()["policies"]	

	for i in listPolicies:
		print("Policy Name / ID: ",i['name'],"  /  ",i['id'])
	
	policyChoice = input("Enter the ID of the poicy you want to use: ")
	
	return policyChoice

#used to get the uuid of the template once we have the policy id
def templateUuid(policyChoice):
	templateInfo = requests.get(url+"policies/"+str(policyChoice),headers=headers,verify=True)
	templateInfo = templateInfo.json()["uuid"]
	templateUuid = str(templateInfo)
	
	return templateUuid

#gets a list of available cloud/local scanners.		
def listScanners():
	scanners = requests.get(url+"scanners/",headers=headers,verify=True)
	listScanners = scanners.json()["scanners"]

	for i in listScanners:
		print("Scanner Name / ID: ",i['name'], "  /  ",i['id'])
	
	scannerChoice = input("Enter the ID of the scanner to be used: ")

	return scannerChoice

# Scan class. takes in the policy id, scanner id of the scanner to use, and the ips to scan
#
# launchScan() is used to kick off the scan
# updateRunningUUID() updates the class with the id of the launched scan
# checkScanStatus(runningUUID) - gets the staus of a runnign scan. takes the scanid from the scan launched

class Scan:
	
	def __init__(self,policyChoice,scannerChoice,ipsToScan):
		self.uuid = templateUuid(policyChoice)
		self.policy = policyChoice
		self.scanner = scannerChoice
		self.hosts = ipsToScan
		self.runningUUID = 0

	def displayHosts(self):
		return self.hosts
	
	def displayScanner(self):
		return self.scanner

	def displayPolicy(self):
		return self.policy
	
	def displayUuid(self):
		return self.uuid

	#updated after the scan is launched with the id. Initially intialized to zero
	def updateRunningUUID(self,uuid):
		self.runningUUID = uuid
	
	#launches the scan in nessus
	#returns the id of the scan launched
	def launchScan(self):
		scan = {"uuid":self.uuid,
			"settings": {
			"name": "api scan", #add something here for the names of scans launched
			"enabled": "true",
			"scanner_id":self.scanner,
			"policy_id":self.policy,
			"text_targets":self.hosts,
			"launch_now":"true"}
			}

		scanData = requests.post(url+"scans",json=scan,headers=headers,verify=True)

		#checks to make sure that there weren't any errors when adding/kicking off the scan
		if(scanData.status_code == 200):
			print("Scan launched successfully")
		else:
			print("Error with launching the scan")		
		
		#parse the response to get the uuid of the running scan
		runningUUID = json.loads(scanData.text)
		runningUUID = runningUUID['scan']['id']
		#return the UUID of the scan launched
		return runningUUID

	#checks whether a scan is running or not
	def checkScanStatus(self):
		scanStatus = True
		#GET /scans/{scan_id}		
		return scanStatus
	
if __name__ == '__main__':
	
	if((len(sys.argv) != 4) and (sys.argv[1] != "help")):
		ipsToScan = input("Enter the ip/ip's to scan: ")
		#list all of the available scan policies
		policyChoice = listPolicies()
		scannerChoice = listScanners()	
		scanUuid = templateUuid(policyChoice)
		#Create the scan
		newScan = Scan(policyChoice,scannerChoice,ipsToScan)	
		runningUUID = newScan.launchScan()		
		newScan.updateRunningUUID(runningUUID)
	#displays infomration about command line arguments	
	elif(sys.argv[1] == "help"):
		print("arg1 - Scan policy ID")
		print("arg2 - Scanner choice ID")
		print("arg3 - IP or cidr to scan")
		print("Hosts can be entered as either a single host/IP, comma seperated hosts, or cidr")

	#if there are command line args then we can go ahead and launch the scan
	else:
		policyChoice = sys.argv[1]
		scannerChoice = sys.argv[2]
		ipsToScan = sys.argv[3]
		newScan = Scan(policyChoice,scannerChoice,ipsToScan)
		runningUUID = newScan.launchScan()		
		newScan.updateRunningUUID(runningUUID)
