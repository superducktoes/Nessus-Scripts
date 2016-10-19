import json
import requests
import urllib
import sys #used for command line arguments

accessKey = ""
secretKey = ""

url = "https://cloud.tenable.com/"
headers = {'X-ApiKeys': 'accessKey=' + str(accessKey) + '; secretKey = ' + str(secretKey) + ';'}

requests.packages.urllib3.disable_warnings()

def listPolicies():
	policies = requests.get(url+"policies/",headers=headers,verify=True)
	listPolicies = policies.json()["policies"]	

	for i in listPolicies:
		print("Policy Name / ID: ",i['name'],"  /  ",i['id'])
	
	policyChoice = input("Enter the ID of the poicy you want to use: ")
	
	return policyChoice

def templateUuid(policyChoice):
	templateInfo = requests.get(url+"policies/"+str(policyChoice),headers=headers)
	templateInfo = templateInfo.json()["uuid"]
	templateUuid = str(templateInfo)
	
	return templateUuid
		
def listScanners():
	scanners = requests.get(url+"scanners/",headers=headers,verify=False)
	listScanners = scanners.json()["scanners"]

	for i in listScanners:
		print("Scanner Name / ID: ",i['name'], "  /  ",i['id'])
	
	scannerChoice = input("Enter the ID of the scanner to be used: ")

	return scannerChoice


class Scan:
	
	def __init__(self,policyChoice,scannerChoice,ipsToScan):
		self.uuid = templateUuid(policyChoice)
		self.policy = policyChoice
		self.scanner = scannerChoice
		self.hosts = ipsToScan
		
	def displayHosts(self):
		return self.hosts
	
	def displayScanner(self):
		return self.scanner

	def displayPolicy(self):
		return self.policy
	
	def displayUuid(self):
		return self.uuid

	def launchScan(self):
		scan = {"uuid":self.uuid,
			"settings": {
			"name": "api scan",
			"enabled": "true",
			"scanner_id":self.scanner,
			"policy_id":self.policy,
			"text_targets":self.hosts,
			"launch_now":"true"}
			}
		scanData = requests.post(url+"scans",json=scan,headers=headers,verify=True)
		

if __name__ == '__main__':

#	if(len(sys.argv) < 3 or len(sys.argv) > 4):
	ipsToScan = input("Enter the ip/ip's to scan: ")
		#list all of the available scan policies
	policyChoice = listPolicies()
	scannerChoice = listScanners()	
	scanUuid = templateUuid(policyChoice)
		
	print("UUID :",scanUuid)	
		#Create the scan
	newScan = Scan(policyChoice,scannerChoice,ipsToScan)	
	print("Using scanner: ", newScan.displayScanner())
	print("Using UUID: ",newScan.displayUuid())
	newScan.launchScan()			
#	else:
#		newScan = Scan(str(sys.argv[0]),str(sys.argv[1]),str(sys.argv[2]))
#		print("Using scanner: ", newScan.displayScanner())
