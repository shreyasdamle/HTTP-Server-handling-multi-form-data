# Data Control Server for the KHP platform #

###Still In Development 

###Status: Active

###Functionality :

Performs the following 

-> decryption of the received data
-> stores received data locally

###Usage: 
$ python data_control.py

###Samle curl command
curl -X POST -F "device_id=12345" -F "access_token=9876"5 -F "file=@<path-to-file>" localhost:8083