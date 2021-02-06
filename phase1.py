!pip install ecpy
!pip install pycryptodome
import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID = 25429

E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator

#HERE CREATE A LONG TERM KEY
def Key_Gen(n,P):
  sL = random.randint(0, n-1) #Private key
  QS = sL*P  #Public key
  cor_x = QS.x
  cor_y = QS.y
  return sL, QS, cor_x, cor_y
  
#sL, QS, cor_x , cor_y = Key_Gen(n,P)
#print("sL:", sL) 
#print("Qs_x:",cor_x)
#print("Qs_y:", cor_y)

sL = 59275929642180827474096070559282890346388566047568109703095050596607456796969

#server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, E)

# HERE GENERATE A EPHEMERAL KEY 
def Sig_Gen(n,m,P,sL):
  k = randint(0,n-1)
  R = k*P #Ephemeral Key
  r = (R.x) %n # x-coordinate
  hash = (SHA3_256.new(m + r.to_bytes((r.bit_length()+7)//8,byteorder='big'))).digest()
  h = int.from_bytes(hash,byteorder = 'big') % n
  s = ((sL*h) + k) % n
  return h,s

def Sig_Ver(s,P,h,QS,n,m):
  V = (s*P)-(h*QS)
  v = (V.x) %n
  h2 = (SHA3_256.new(m + v.to_bytes((v.bit_length()+7)//8,byteorder='big'))).digest()
  new_h = int.from_bytes(h2,byteorder = 'big') % n 
  if(h == new_h):
    return True
  else:
    return False

m = str(stuID).encode("UTF-8")
h,s = Sig_Gen(n,m,P,sL)

if Sig_Ver(s,P,h,QS,n,m):
 print("Signature verifies.")
else:
  print("Signature not verifies.")  


try:
	#REGISTRATION
	#mes = {'ID':stuID, 'h': h, 's': s, 'LKEY.X': cor_x, 'LKEY.Y': cor_y}
	#response = requests.put('{}/{}'.format(API_URL, "RegStep1"), json = mes)		
	#if((response.ok) == False): raise Exception(response.json())
	#print(response.json())

	#print("Enter verification code which is sent to you: ")	
	#code = int(input())

	#mes = {'ID':stuID, 'CODE': code}
	#response = requests.put('{}/{}'.format(API_URL, "RegStep3"), json = mes)
	#if((response.ok) == False): raise Exception(response.json())
	#print(response.json())



	#STS PROTOCOL
  Sa, Qa, cor2_x , cor2_y= Key_Gen(n,P)
  print("Sa:",Sa) 
  print("Qa_x:",cor2_x)
  print("Qa_y:",cor2_y)

  mes = {'ID': stuID, 'EKEY.X': cor2_x, 'EKEY.Y': cor2_y}
  response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json = mes)
  if((response.ok) == False): raise Exception(responce.json())
  res = response.json()

  Sa =  48753863680470641392388712174624831782756104239579376105559854626965854271616

	#calculate T,K,U
  QB = Point(115387858341009215005049043443742739870807827787720573993258640245878230603604,85021174615600057429417835542118953092990743727832975663580255937626798652393,E) 
  T = Sa * QB
  #print("T:",T)

  U = str(T.x) + str(T.y) + 'BeYourselfNoMatterWhatTheySay' #Desired U version
  #print("U:",U) 

  K = SHA3_256.new(str(U).encode('UTF-8')).digest() #Session Key
  #print("K:",K)


	#Sign Message
  W1 = str(cor2_x) + str(cor2_y) + str(QB.x) + str(QB.y)
  #print("W1:",W1)

  W1 = str(W1).encode('UTF-8')
  h_,s_ = Sig_Gen(n,W1,P,sL)


	# Encyption
  plaintext = "s" + str(s_) + "h" + str(h_)
  #print("Plaintext:", plaintext) 

  ptext = str(plaintext).encode('UTF-8')
  cipher = AES.new(K,AES.MODE_CTR)

  Y1 = cipher.nonce + cipher.encrypt(ptext)
  #print("ctext:",Y1) 
  int_of_Y1 = int.from_bytes(Y1,byteorder = 'big')  
  #print("ctext:",int_of_Y1) 



	###Send encrypted-signed keys and retrive server's signed keys
  mes = {'ID': stuID, 'FINAL MESSAGE': int_of_Y1}
  response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json = mes)
  if((response.ok) == False): raise Exception(response.json()) 
  ctext2 = response.json()


	#Decrypt 
  ctext2 = ctext2.to_bytes((ctext2.bit_length()+7)//8,byteorder='big')

  cipher = AES.new(K, AES.MODE_CTR, nonce=ctext2[0:8])
  #print(cipher)
  dtext = cipher.decrypt(ctext2[8:])
  dtext = dtext.decode('UTF-8')
  #print("Decrypted text: ", dtext)


	#verify
  index = dtext.find("h")
  s2 = dtext[2:index]
  h2 = dtext[index+1:]

  s2 = int(s2)
  h2 = int(h2)

  W2 = str(QB.x) + str(QB.y) + str(Qa.x) + str(Qa.y)
  W2 = str(W2).encode('UTF-8')

  if Sig_Ver(s2,P,h2,QSer_long,n,W2):
    print("Signature verifies.")
  else:
    print("Signature not verifies.")


	#get a message from server for 
  mes = {'ID': stuID}
  response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
  ctext3 = response.json()     
	

	#Decrypt
  ctext3 = ctext3.to_bytes((ctext3.bit_length()+7)//8,byteorder='big')

  cipher = AES.new(K, AES.MODE_CTR, nonce=ctext3[0:8])
  #print(cipher)
  dtext2 = cipher.decrypt(ctext3[8:])
  dtext2 = dtext2.decode('UTF-8')
  print("Decrypted text:", dtext2)


	#Add 1 to random to create the new message and encrypt it

  RAND = dtext2.partition(".")[2]
  RAND = int(RAND) + 1

  ct = "When you read this message I'll be far away. " + str(RAND)
  print("Decrypted text:", ct)


	
	#send the message and get response of the server
  mes = {'ID': stuID, 'ctext': ct}
  response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json = mes)
  ctext4 =response.json()
  print("Expected message from server:", ctext4)       


except Exception as e:
	print(e)