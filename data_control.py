#!/usr/bin/python


import SimpleHTTPServer
import SocketServer
import logging
import cgi
import sys
from Crypto import Random
from Crypto.Cipher import AES
import base64
from Crypto.Hash import SHA512


if len(sys.argv) > 2:
    PORT = int(sys.argv[2])
    I = sys.argv[1]
elif len(sys.argv) > 1:
    PORT = int(sys.argv[1])
    I = ""
else:
    PORT = 8083
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
        access_token = form.getvalue("access_token")
        enc_data = form.getvalue("file")
        print "Received msg from the Data Collection Server: " + enc_data

        #Decryption Module
        enc_data = base64.b64decode(enc_data)
        BS = 16 #Block Size of AES
        unpad = lambda s : s[0:-ord(s[-1])]
        salt = "abcdefgh" #Salt Value
        key = "0123456789abcdef" #Encryption Key
        iv = enc_data[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(enc_data[16:]))
        print "Decrypted msg: " + plaintext
        print "**** " + "Device ID: " + device_id + " Access Token: " + access_token + " Data: " + plaintext + " ****"
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

Handler = ServerHandler

httpd = SocketServer.TCPServer(("", PORT), Handler)

print "Serving at: http://%(interface)s:%(port)s" % dict(interface=I or "localhost", port=PORT)
httpd.serve_forever()
