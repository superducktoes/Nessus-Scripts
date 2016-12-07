from bottle import route,run,template,get,post,request
import requests
import json

#replace these with the keys for the account used for scanning
accessKey = ""
secretKey = ""

url = "https://cloud.tenable.com/"
headers = {'X-ApiKeys': 'accessKey=' + str(accessKey) + '; secretKey = ' + str(secretKey) + ';'}

#gets a list of available policies
def listPolicies():
    policies = requests.get(url+"policies/",headers=headers,verify=True)
    listPolicies = policies.json()["policies"]

    return listPolicies

def listScanners():
    scanners = requests.get(url+"scanners/",headers=headers,verify=True)
    listScanners = scanners.json()["scanners"]

    return listScanners

HOST="0.0.0.0"

policies = listPolicies()
scanners = listScanners()

def testPrint(hosts):
    print(hosts)
    
@route("/")
def serveHome():
    hosts = request.forms.get('hosts')
    testPrint(hosts)
    return template("disp_table",
                    policyRows=policies,
                    scannerRows=scanners)

run(host=HOST, port=8080, debug=False)
