#!/usr/bin/python


import SimpleHTTPServer
import SocketServer
import logging
import cgi
import sys
import base64
import json
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

class ThreadingSimpleServer (ThreadingMixIn, HTTPServer):
    pass


defaults = json.loads(open('config.json').read())

if len(sys.argv) > 2:
    PORT = int(sys.argv[2])
    I = sys.argv[1]
elif len(sys.argv) > 1:
    PORT = int(sys.argv[1])
    I = ""
else:
    PORT = defaults["PORT"]
    I = ""


class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

    def do_GET(self):
        logging.warning("======= GET STARTED =======")
        logging.warning(self.headers)
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        logging.warning("======= POST STARTED =======")
        logging.warning(self.headers)
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        logging.warning("======= POST VALUES =======")
        list1 = form.list
        for item in form.list:
            print type(item)
            logging.warning(item)
        logging.warning("\n")
        device_id = form.getvalue("device_id")
        hashed_msg = form.getvalue("hash") 
        enc_data = form.getvalue("file")
        print "Received msg from the Data Collection Server: " + enc_data
        
        
        #Integrity Check Module
        #salt = defaults["SALT"] #Salt Value
        enc_data = base64.b64decode(enc_data)
        message_hash = SHA512.new()
        message_hash.update(enc_data)
        message_hash = base64.b64encode(message_hash.digest())
        hashed_msg =  hashed_msg.replace("\n", "")
        print "\n\n\n" + hashed_msg + "\n\n\n" + message_hash

        if message_hash == hashed_msg:
        
        #Decryption Module
            #enc_data = base64.b64decode(enc_data)
            BS = 16 #Block Size of AES
            unpad = lambda s : s[0:-ord(s[-1])]
            key = defaults["KEY"] #Encryption Key
            iv = enc_data[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(enc_data[16:]))
            print "Decrypted msg: " + plaintext
            print "**** " + "Device ID: " + device_id  + " Data: " + plaintext + " ****"
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
        
        else:
            print "Status: Error | Integrity Check Failed!" 
        

Handler = ServerHandler

httpd = ThreadingSimpleServer(("", PORT), Handler)

print "Serving at: http://%(interface)s:%(port)s" % dict(interface=I or "localhost", port=PORT)
httpd.serve_forever()
