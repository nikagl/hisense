# Communication script for Hisense with token access authentication

Based on information found in "Identifier rejected on 55U7KQ" topic:
https://github.com/Krazy998/mqtt-hisensetv/issues/14

1. Find the certificates needed from the topic mentioned above and add them to the same folder.
2. Make sure to replace the ip-address with the IP of your TV.
3. Run the script "python hisense.py"
4. The script will request access when executed the first time. It will automatically renew the accesscode with the refreshcode when it expires.

It allows a range of commands to be entered from a prompt (with no command line parameters added) or using the command line. 

See help after running it for the first time (or with command line parameter "--action help"):

```
1. Get TV State, from command line: --action getstate
2. Power Cycle TV, from command line: --action powercycle (of use poweron or poweroff which first gets the state)
3. Get Source List, from command line: --action getsourcelist
4. Change Source, from command line: --action changesource --parameter <source_name>
5. Get Volume, from command line: --action getvolume
6. Change Volume, from command line: --action changevolume --parameter <volume>
7. Get App List, from command line: --action getapplist
8. Launch App, from command line: --action launchapp --parameter <app_name>
9. Send key, from command line: --action sendkey --parameter <key>

D. Toggle Debug Mode, from command line: --debug True/False
N. New Authentication toggle, from command line: --newauth True/False

A. Authenticate, from command line: --action authenticate
C. Show Credentials, from command line: --action showcredentials
R. Refresh Token, from command line: --action refreshtoken
F. Force Refresh Token, from command line: --action forcerefresh

S. Save Credentials, from command line: --action save
L. Load Credentials, from command line: --action load

H. Help, from command line: --action help

0. Exit, from command line: --action exit
```
