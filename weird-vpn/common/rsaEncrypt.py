import rsa
#user inputs name of existing message file, name of the file to store the 
#encrypted message, the public and private key file names, and
#the name of the signature file
def encrypt(filename, encryptfilename, publicfile, privatefile, signame):
	
	#Step 1: open and reads chosen file
	
	with open(filename, mode='r') as messagefile:
		message = messagefile.read()
	
	#Step 2: encodes message utf8
	
	#print(message)
	encodedMessage = message.encode('utf8')
	#print(encodedMessage)
	
	#Step 3: retrieves public and private keys

	with open(privatefile, mode='rb') as privatefile:
		keydata = privatefile.read()
	privkey = rsa.PrivateKey.load_pkcs1(keydata)

	with open(publicfile, mode='rb') as publicfile:
		keydata = publicfile.read()
	pubkey = rsa.PublicKey.load_pkcs1(keydata)

	#print(privkey)
	#print(pubkey)
	
	#Step 4: signs message with SHA-1 hash and save signature to file

	signature = rsa.sign(encodedMessage, privkey, 'SHA-1')
	#print('signature is:')
	#print(signature)

	with open(signame, mode="wb") as sigfile:
		sigfile.write(signature)
		
	#Step 5: encrypts message and saves to file

	crypto = rsa.encrypt(encodedMessage,pubkey)
	#print('encrypted message: ')
	#print(crypto)

	with open(encryptfilename, mode="wb") as cryptofile:
		cryptofile.write(crypto)
