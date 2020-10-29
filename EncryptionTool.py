#
# Imperative script for encrypting and decrypting files and directories
# using AES encryption. File and directory data is encoded in binary.
# File and directory names are encoded in base32 after converstion from binary.
#

import os
import sys
import hashlib
import base64
from Crypto.Cipher import AES

#default password is "admin"
password = "admin"

#use cipher feeback mode
mode = AES.MODE_CFB

#size of buffer for containing file data
BYTE_BUFFER_SIZE = 1024


#retrieve 256-bit key from password
def getKey():
	#get first 64 hex chars from hash of password
	keyBase = hashlib.sha256(password.encode()).hexdigest()[0:64]
	
	#convert hex to byte array
	key = bytes.fromhex(keyBase)

	return key
	
def getEncryptedWord(word):
	#create encryption scheme from key
	key = getKey()
	aesEncryptor = AES.new(key, mode)
	
	#encrypt word argument and translate to base32
	cipherText = aesEncryptor.encrypt(word.encode("utf-8"))
	finalWord = base64.b32encode(aesEncryptor.iv + cipherText).decode("utf-8")
	
	return finalWord

def getDecryptedWord(word):
	#decode from base32
	firstword = base64.b32decode(word)

	#retrieve initialization vector
	iv = firstword[0:16]

	#create decryption scheme from key
	key = getKey()
	aesDecryptor = AES.new(key, mode, iv)
	
	#decrypt text starting after iv
	text = aesDecryptor.decrypt(firstword[16:]).decode("utf-8")
	return text

def encryptFile(path):
	#obtain key and initialization vector for AES encryption
	key = getKey()

	#create encryptor
	aesEncryptor = AES.new(key, mode)
	
	#set up to find encrypted name of file
	newFileName = ''
	newFileDir = ''
	
	#separate name of file from directory it is in
	if '/' in path:
		newFileName = path[path.rfind('/') + 1:]
		newFileDir  = path[0:path.rfind('/') + 1]
	else:
		newFileName = path
		newFileDir  = './'
		
	#encrypt name of file
	newFileName = getEncryptedWord(newFileName)
	#create new path for encrypted file
	fullNewFilePath = newFileDir + newFileName
	
	#set up buffer to contain bytes
	byteBuffer = list()
	i = 0
	
	#open output file and write initialization vector
	outFile = open(fullNewFilePath, 'wb')
	outFile.write(aesEncryptor.iv)
	
	#open input file to encrypt, and read a byte
	inFile = open(path, 'rb')
	currentByte = inFile.read(1)

	#while there are still unread bytes in the file
	while(currentByte):
		#place the next byte in the buffer
		byteBuffer.append(currentByte)
		i += 1
		
		#if the buffer has reached its limit
		if(i == BYTE_BUFFER_SIZE):
			#encipher text and insert into new file
			text = b''.join(byteBuffer)
			cipherText = aesEncryptor.encrypt(text)
			outFile.write(cipherText)
			byteBuffer.clear()
			i = 0
		
		#read next byte
		currentByte = inFile.read(1)

	#encipher remaining text and insert into file
	if len(byteBuffer) > 0:
		text = b''.join(byteBuffer)
		cipherText = aesEncryptor.encrypt(text)
		outFile.write(cipherText)
	
	#close files
	inFile.close()
	outFile.close()
	
	#remove original file
	os.remove(path)


def decryptFile(path):
	#obtain key and initialization vector for AES decryption
	key = getKey()
	
	#open file to decrypt
	inFile = open(path, 'rb')
	#read initialization vector
	iv = inFile.read(16)
	#create decryptor
	aesDecryptor = AES.new(key, mode, iv)

	#set up to find decrypted name of file
	newFileName = ''
	newFileDir = ''
	
	#separate name of file from directory it is in
	if '/' in path:
		newFileName = path[path.rfind('/') + 1:]
		newFileDir  = path[0:path.rfind('/') + 1]
	else:
		newFileName = path
		newFileDir  = './'
		
	#decrypt name of file
	newFileName = getDecryptedWord(newFileName)
	#create new path for decrypted file
	fullNewFilePath = newFileDir + newFileName
	

	#open output file
	outFile = open(fullNewFilePath, 'wb')


	#set up buffer to contain bytes
	byteBuffer = list()
	i = 0
	
	
	#read first byte of cipher data
	currentByte = inFile.read(1)
	
	#while there is still cipher data to read
	while(currentByte):
		#add next byte of cipherText to buffer
		byteBuffer.append(currentByte)
		i += 1
		
		#if the buffer has reached its limit
		if(i == BYTE_BUFFER_SIZE):
			#decipher text
			cipherText = b''.join(byteBuffer)
			text = aesDecryptor.decrypt(cipherText)
			outFile.write(text)
			byteBuffer.clear()
			i = 0

		#read next byte
		currentByte = inFile.read(1)

	#decipher remaining text and insert into file
	if len(byteBuffer) > 0:
		cipherText = b''.join(byteBuffer)
		text = aesDecryptor.decrypt(cipherText)
		outFile.write(text)
		
	#close files
	inFile.close()
	outFile.close()
	
	#remove original file
	os.remove(path)
	


def encryptDirectory(path):
	#obtain list of files in current directory
	fileList = os.listdir(path)
	
	#loop over list of files
	for i in fileList:
		#for the encryption tool file, do nothing
		if i == sys.argv[0]:
			pass
			
		#for a directory, recursively encrypt files inside
		elif os.path.isdir(path + "/" + i):
			
			encryptDirectory(path + "/" + i)
			
			#rename directory to aes converted to base32
			newName = getEncryptedWord(i)
			os.rename(path + "/" + i, path + "/" + newName)
		
		#for a file, encrypt the file
		elif os.path.isfile(path + "/" + i):
			encryptFile(path + "/" + i)
			
		else:
			print(path + " is not valid")
			
def decryptDirectory(path):
	#obtain list of files in current directory
	fileList = os.listdir(path)
	
	#loop over list of files
	for i in fileList:
		#for the encryption tool file, do nothing
		if i == sys.argv[0]:
			pass
			
		#for a directory, recursively decrypt files inside
		elif os.path.isdir(path + "/" + i):

			decryptDirectory(path + "/" + i)
			
			#rename directory from base32 to original
			newName = getDecryptedWord(i)
			os.rename(path + "/" + i, path + "/" + newName)
			
		#for a file, decrypt the file
		elif os.path.isfile(path + "/" + i):
			decryptFile(path + "/" + i)
			
		else:
			print(path + " is not valid")

if __name__ == "__main__":

	#flag for successfully typed command
	usageFail = False

	#tool must be used with three arguments, second argument is -e or -d
	#final argument is the name of a file or directory
	#tool cannot encrypt itself
	if len(sys.argv) == 3:
		if sys.argv[1] == '-e' or sys.argv[1] == '-d':
			if os.path.exists(sys.argv[2]) and sys.argv[2] != sys.argv[0]:
			
				try:
					#encrypt directory
					if  (sys.argv[1] == '-e' and os.path.isdir(sys.argv[2])):

						#accept password from user for encrypting
						password = input("select a password: ")
						
						print("Encrypting directory " + sys.argv[2])
						encryptDirectory(sys.argv[2])
					
					#encrypt file
					elif(sys.argv[1] == '-e' and os.path.isfile(sys.argv[2])):
					
						#accept password from user for encrypting
						password = input("select a password: ")
					
						print("Encrypting file " + sys.argv[2])
						encryptFile(sys.argv[2])
						
					#decrypt directory
					elif(sys.argv[1] == '-d' and os.path.isdir(sys.argv[2])):
					
						#accept password from user for decrypting
						password = input("enter password: ")
					
						print("Decrypting directory " + sys.argv[2])
						decryptDirectory(sys.argv[2])
						
					#decrypt file
					elif(sys.argv[1] == '-d' and os.path.isfile(sys.argv[2])):
					
						#accept password from user for decrypting
						password = input("enter password: ")
					
						print("Decrypting file " + sys.argv[2])
						decryptFile(sys.argv[2])
						
					else:
						usageFail = True
						
				except UnicodeDecodeError:
					print("Decryption Failed: Incorrect Password")

				except:
					print("Failed")
			else:
				usageFail = True
		else:
			usageFail = True
	else:
		usageFail = True
		
	#inform user of usage
	if usageFail:
		print("usage (cannot encrypt this python tool itself): ")
		print("encrypt: python " + sys.argv[0] + " -e [file|directory]" )
		print("decrypt: python " + sys.argv[0] + " -d [file|directory]" )



