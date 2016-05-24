#Use this code as a reference to implement public key encryption

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256

clientmap = {} #List for multiple clients, name and public key

print 'Generating RSA keys ....'
server_privkey = RSA.generate(4096, os.urandom)
server_pubkey = server_privkey.publickey()
sign = server_privkey


#Sample Encryption
def send_encrypted (client, message):
    encryptor = clientmap[client][2]
    msg = encryptor.encrypt(message)
    message_hash = SHA256.new()
    message_hash.update(message)
    signkey = sign
    
    #Append Signature
    signer = PKCS1_PSS.new(signkey)
    signature = signer.sign(message_hash)
    messasge = '%s#^[[%s' % (msg, signature)


#Verify Signature
def verify_signature(client, message, signature):
    key = clientmap[client][2]
    msg_hash = SHA256.new()
    msg_hash.update(message)
    verifier = PKCS1_PSS.new(key)
    return verifier.verify(msg_hash, signature)


# Get client public key and send our public key
pubkey = RSA.importKey(receive(client))
send(client, self.server_pubkey.exportKey())


#Sample Decryption
if data:
    dataparts = data.split('#^[[')
    signature = dataparts[1]
    data = dataparts[0]
    verified = verify_signature(client, data, signature)
    data = server_privkey.decrypt(data)