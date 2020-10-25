import rsa
#uses rsa library to generate keys
#when calling funtion, user chooses keysize and the name of
#the files that are going to store the public and private keys
#IMPORTANT: key files must end in .pem
def generateKeys(keysize, cores, publicfilename, privatefilename):
	
	#Step 1: generate keys
	#poolsize refers to number of cores used to process key generation
	
	#print("generating keys")
	(pubkey, privkey) = rsa.newkeys(keysize, poolsize=cores)
	#print("keys generated")
	#print(pubkey)
	#print(privkey)
	
	#Step 2: format for PEM
	
	pubkeyPEM = pubkey.save_pkcs1('PEM')
	#print(pubkeyPEM)

	privkeyPEM = privkey.save_pkcs1('PEM')
	#print(privkeyPEM)
	
	#Step 3: write to files

	with open(privatefilename, mode='wb') as privatefile:
		privatefile.write(privkeyPEM)
	
	with open(publicfilename, mode='wb') as publicfile:
		publicfile.write(pubkeyPEM)
	
