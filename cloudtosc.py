​
#Exports scan data from Nessus and imports into SecurityCenter with historical data
import requests
import json
import time
import urllib
import urllib.request as urllib2
import datetime
import time
import os

#Change these to access key and secret key generated in the users account
accessKey = ""
secretKey = ""

#No need to change this
url = "https://cloud.tenable.com/"
headers = {'X-ApiKeys': 'accessKey=' + str(accessKey) + '; secretKey = ' + str(secretKey) + ';'}

scUrl = ""  #REMOVE LATER. ONLY FOR TESTING
login = ''
password = ''

requests.packages.urllib3.disable_warnings()

#prints a list of scans that are set for the user
def listScans():
    scans = requests.get(url+"scans",headers=headers,verify=False)
    list = scans.json()["scans"]
    for i in list:
        print("> ",i['name']," ===>  Scan ID: ",i['id'])

    scanChoice = input("What is the ID of the scan that you want to migrate? ")
   
    #Requests the details based on the scan id. If it exists we'll return it to main
    #If a 200 response is not returned we'll prompt for the user to try again.
   
    exists = requests.get(url+"scans/"+str(scanChoice),headers=headers)

# Still need to loop to prompt the user until they enter a valid scan id.   
    if(exists.status_code == 200):
        print("Scan Exists")
    else:
        print("Scan does not exist")

    return scanChoice

#Gets all of the historical scan results and downloads them
def getHistory(scanChoice):
   
    #creates a stack for storing historical ids
    historyID = []
    history = requests.get(url+"scans/"+str(scanChoice),headers=headers,verify=False)

    #filters down to just the historical information
    listHistory = history.json()["history"]
    #gets a list of the history_id and adds it to the stack
    for i in listHistory:
        historyID.append(i['history_id'])
   
    #returns a list of history_ids to be downloaded   
    return historyID

#saves the .nessus file
def downloadFiles(historyID,scanChoice):
   
    #gets the number of elements in the stack
    stackSize = len(historyID)
    counter = 1
    payload = {"format":"nessus"}

    for i in historyID:
        print("Downloading file ",counter," of ",stackSize)

        choice = str(scanChoice)
        history = str(i)

#        Need to include the params to include the history id
        fileNumber = requests.post(url+"scans/"+choice+"/export?history_id="+history, headers=headers,data=payload,verify=False)
       
        #strips the download id from what is returned when exporting the history_id and scan_id
        fileDownload =     str(fileNumber.text)[8:]
        fileDownload = fileDownload.strip("}")
       
        #exports the .nessus file
        result = urllib2.Request(url+"scans/"+choice+"/export/"+fileDownload+"/download", headers=headers)
        #give it a few seconds before writing the results to file
        time.sleep(2)
        #reads in the contents of the exported nessus file above
        contents = urllib2.urlopen(result).read().decode("utf-8")

#        leaving this in for right now. shows the output of the .nessus files being saved
#        print(contents)

        #writes the file
        file = open(history,"w")
        file.write(contents)
        file.close()           
        #give it a few more seconds before requesting the next file
        time.sleep(3)
   
        counter = counter + 1

#gets the timestamp for each scan and then converts it before adding to the stack
def getTimestamp(historyID,scanChoice):

    scanChoice = str(scanChoice)
    timestampStack = []

    for i in historyID:

        #lets get the timestamp from the scans first
        historyParam = {'history_id':i}
        timeStamp = requests.get(url+"scans/"+scanChoice,headers=headers,params=historyParam,verify=False)
        getTimestamp = timeStamp.json()["info"]

        #start converting unix timestamp
        unixTime = getTimestamp['timestamp']
        convertedTime = datetime.datetime.fromtimestamp(int(unixTime)).strftime('%d %B %Y')

        #add the dates to the stack
        timestampStack.append(convertedTime)
   
    return timestampStack

#gets the information needed to log into SecurityCenter
def getTokenCookie():
    headers = {'Content-type': 'application/json'} #default header for getting token
    sc = requests.request('post', scUrl+'/rest/token',
                data=json.dumps({'username':login, 'password':password}),
                headers=headers,
                verify=False)
   

    cookie = sc.cookies

    token = sc.json()['response']['token']
    login_header = {'X-SecurityCenter':str(token)}
    headers.update(login_header)

    return(cookie,headers)


#def addToSC():
   
#uploads the scan results
#set the time based on the original scan time
#upload the files.
#nightly cleanup
#set the new time
#loop through to the next   

# Uploads the scan results to the SecurityCenter console
#
#    cookie,token - used for auth to SecurityCenter
#    historyID - stack for ID of the scan files downloaded
#    timestampStack - stack with the timestamps of each scan launched

def uploadResults(cookie,token,historyID,timestampStack):
   
    #gets the length of the stack. used to loop through
    loopStop = (len(historyID))
    stopDate = "'" + str(timestampStack[0]) + "'"

    #need to run this after each import
    nightlyCleanupCommand = "su - tns -c " + "'" + "/opt/sc/support/bin/php -f /opt/sc/src/tools/nightlyCleanup.php" + "'"

    #sets the date on the local server to the first date on the stack
    dateCommand = "date -s %s" % stopDate
    os.system(dateCommand)       
    #need to run the nightly cleanup   
    os.system(nightlyCleanupCommand)

    #loop through thet history and timestamp to start uploading the files to SecurityCenter
    #right now its just looping through and printing out the content

    for i in timestampStack:
        print("Setting date to ",i)
        date = "'" + str(i) + "'"
        dateCommand = "date -s %s" % date
        os.system(dateCommand)
       
        # This is where the files get uploaded to SecurityCenter
        # /opt/sc/src/tools/parseNessusFile.php
        # parseNessusFile <nessus file location> <repID> <orgID> <userID> <groupID>
   
        #Run the cleanup again after uploading the files
        os.system(nightlyCleanupCommand)

if __name__ == '__main__':
    print("Getting a list of scans")
    scanChoice = listScans()
    #Now that we have a list of scan ids lets get all of the .nessus files
    historyID = getHistory(scanChoice) #passes the scan id the user selected
    print(historyID)
    downloadFiles(historyID,scanChoice)
    timestampStack = getTimestamp(historyID,scanChoice)
    print("\n\n\n")

    print(historyID)
    print(timestampStack)

    print("Nessus files finished downloading")
    print("Let's start moving the scan results over to SecurityCenter.")
    scUsername = input("Enter the SecurityCenter username: ")
    scPassword = input("Enter the SecurityCenter password: ")
   
    cookie,token = getTokenCookie()   
   
    uploadResults(cookie,token,historyID,timestampStack)