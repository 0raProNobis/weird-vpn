import rsa
#user specifies the name of the file to decrypt, the message sig file,
#the public and private key file names, and the name of the file to save to
def decrypt(encryptfilename, signame, publicfilename, privatefilename, savefilename):
	
	#Step 2: reads key files, encrypted file and sig file
	
	with open(privatefilename, mode='rb') as privatefile:
		keydata = privatefile.read()
	privkey = rsa.PrivateKey.load_pkcs1(keydata)
	
	with open(publicfilename, mode='rb') as publicfile:
		keydata = publicfile.read()
	pubkey = rsa.PublicKey.load_pkcs1(keydata)
	
	with open(encryptfilename, mode='rb') as cryptofile:
		crypto = cryptofile.read()
		
	with open(signame, mode='rb') as sigfile:
		signature = sigfile.read()
		
	#print(privkey)
	#print(pubkey)
	#print(crypto)
	#print(signature)
	
	#Step 2: decrypt message

	decryptedMessage = rsa.decrypt(crypto,privkey)
	#print('decrypted message is: ')
	#print(decryptedMessage)
	
	#Step 3: verifyies message integredy using sig
	#will return false if corrupted

	rsa.verify(decryptedMessage, signature, pubkey)
	
	#Step 4: decodes message

	decodedMessage = decryptedMessage.decode('utf8')

	#print(decodedMessage)
	
	#Step 5: saves decrypted message to file
	
	with open(savefilename, mode='w') as savefile:
		savefile.write(decodedMessage)
