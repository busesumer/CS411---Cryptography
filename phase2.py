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
from Crypto.Hash import HMAC, SHA256
API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID =  25429

E = Curve.get_curve('secp256k1')
n = E.order
P = E.generator
m = str(stuID).encode("UTF-8")

#create a long term key
def Key_Gen(n,P):
  sL = random.randint(0, n-1) #Private key
  QS = sL*P  #Public key
  cor_x = QS.x
  cor_y = QS.y
  return sL, QS, cor_x, cor_y 

def Sig_Gen(n,m,P,sL):
  k = randint(0,n-1)
  R = k*P #Ephemeral Key
  r = (R.x) %n # x-coordinate
  hash = (SHA3_256.new(m + r.to_bytes((r.bit_length()+7)//8,byteorder='big'))).digest()
  h = int.from_bytes(hash,byteorder = 'big') % n
  s = ((sL*h) + k) % n
  return h,s


sL, QS, cor_x , cor_y = Key_Gen(n,P)
print("sL:", sL) 
print("Qs_x:",cor_x) 
print("Qs_y:", cor_y) 

sL = 104175367076914326589315355110254149906388232504471115382108254335944145915049
cor_x = 52522362898937574446649104395157664218817539842459488937093477174042988208988
cor_y = 51153943164442847737135695700228214089166661506346754470329090767832806017808
h = 10898174674750838769724916486025397328425140625183879865566851971393580506409
s = 95225058057239335217911490463623382578889053417588667556035128164530800895650

h,s = Sig_Gen(n,m,P,sL)
print("h:",h) 
print("s:",s) 

#server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9 , 0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, E)


####Register Long Term Key
#mes = {'ID':25429, 'H':h, 'S':s, 'LKEY.X':cor_x, 'LKEY.Y':cor_y}
#response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json = mes)
#print(response.json())

#code = input()

#mes = {'ID':25429, 'CODE': code}
#response = requests.put('{}/{}'.format(API_URL, "RegLong"), json = mes)
#print(response.json())

####Send ephemeral key
for i in range(0,10):
  sA_i, QA_i, cor_x_i , cor_y_i = Key_Gen(n,P)
  print("")
  print("sA"+str(i)+":",sA_i)
  print("ekey"+str(i)+".x:", cor_x_i)
  print("ekey"+str(i)+".y:", cor_y_i)

  h_i, s_i = Sig_Gen(n,(str(QA_i.x)+str(QA_i.y)).encode("UTF-8"),P,sL)
  print("h"+str(i)+":",h_i)
  print("s"+str(i)+":",s_i)

  mes = {'ID': stuID, 'KEYID': i , 'QAI.X':cor_x_i, 'QAI.Y':cor_y_i ,'Si':s_i, 'Hi':h_i}
  response = requests.put('{}/{}'.format(API_URL, "SendKey"), json = mes)
  print(response.json())

####All of the ephemeral keys I sent 
Sa_ = {'0':[88477392762203948376351127113568626270412487558909481964512526546462579137555,51142262319950145002398104032665731257627215224700265132413750162397132248264,106026378205753319329519686123840135286282593202472831247913174143990896740734],
 '1':[12386142152000741466200624826513591196584722148896794225757751365432407283100,85222172796426494323748638802296991791803179018078968939955412473477632750024,50856231759051474454240718804983105635176102931080046057104153174704475167997],
 '2':[44279296113187269391032082192943129170002221525119810924156799498156666448705,27272175640489668532892845323906487949094764694570396275763641868484416606897,58165765231320099765817384514444886541033290131497973433218506767727048994025],
 '3':[102496785990938035195088028792600845585414389432471280195037247510811482518860,61010124770812414696818178033489744572508633957628073164714920248249985581205,49224005792302762239018190021318557404390372460846567351557600873564553492837],
 '4':[13757728523795338698866870917782286288943489324998642904046324871491749195841,36358799823085622937626558265971781511138533559654702475399915365142848901218,16947607239926667924788405796875209682091239351986994296216882100988119278543],
 '5':[103601281702818450418985161993345031509502627632093749785828346380593948048100,1680582773570199299993203793185683609240440409648977784713535821572424024485,59509419003445110453096600663740852523964575846329440342040974991089856812895],
 '6':[113049736374529247383230908304257980068431303215660607824386161870541435871935,97128311553792469201310933036537195224566312211230099700805828050148318429554,112185871505527189184719341475712306496521275173445721313544955417124276904544],
 '7':[98786286059175140282297214869236973894635661593163659819795849990996402186463,77963650600830500554651508032722153583678986875404135881509228254646842435991,102640799139248121216203188729603406573047546904407649028675679315285093136788],
 '8':[38487488292531308809766211370034474874962268098631818055152388710681313977908,101464328651837164319098175169769008315233983518223766337223866444784486852869,114940356288632553210304565801963248053808397500311447425883816523004607453711],
 '9':[65351828659830643183460294878300500456325873784526339977110990446793307534592,84156487235264318198004237310377174218093269000232025445549200571819532971501,102173357766825093110313246957916713938099468894250037298571994465461168846324]
 }

####Receiving Messages
h,s = Sig_Gen(n,m,P,sL)
mes = {'ID_A': stuID, 'S': s, 'H': h}

for i in range(0,5):
  response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
  res = response.json()
  print(res)

  
  i = res['KEYID']
  MSG = res['MSG'] 
  MSG = MSG.to_bytes((MSG.bit_length()+7)//8,byteorder='big')
  ctext = MSG[:-32]
  hmac = MSG[-32:]         

  QBJ = Point(res['QBJ.X'],res['QBJ.Y'],E)
  #print(QBJ)

  ####Verify HMAC
  T = Sa_[str(i)][0] * QBJ
  #print("T:",T)

  U = str(T.x)+str(T.y)+ 'NoNeedToRunAndHide'
  U = str(U).encode('UTF-8')
  #print("U:",U)

  K_ENC = SHA3_256.new(U).digest()
  K_MAC = SHA3_256.new(K_ENC).digest()
  #print("K_ENC:",K_ENC)
  #print("K_MAC:",K_MAC)

  h = HMAC.new(K_MAC, digestmod=SHA256)
  h.update(MSG[8:-32])
  try:
    h.verify(hmac)
    print("The message is authentic")
  except ValueError:
    print("The message or the key is wrong")

  ####Decryption
  cipher = AES.new(K_ENC, AES.MODE_CTR, nonce=ctext[0:8])
  #print(cipher)
  dtext = cipher.decrypt(ctext[8:])
  dtext = dtext.decode('UTF-8')
  print("Decrypted text: ", dtext)

####Send decrypted messages to server
dtext1 = "https://www.youtube.com/watch?v=379oevm2fho"
mes = {'ID_A': stuID, 'DECMSG': dtext1}
response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
print(response.json())

dtext2 = "https://www.youtube.com/watch?v=Q8Tiz6INF7I"
mes = {'ID_A': stuID, 'DECMSG': dtext2}
response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
print(response.json())

dtext3 = "https://www.youtube.com/watch?v=1hLIXrlpRe8"
mes = {'ID_A': stuID, 'DECMSG': dtext3}
response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
print(response.json())

dtext4 = "https://www.youtube.com/watch?v=1hLIXrlpRe8"
mes = {'ID_A': stuID, 'DECMSG': dtext4}
response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
print(response.json())

dtext5 = "https://www.youtube.com/watch?v=Q8Tiz6INF7I"
mes = {'ID_A': stuID, 'DECMSG': dtext5}
response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
print(response.json())


###delete ephemeral keys
#h,s = Sig_Gen(n,m,P,sL)
#mes = {'ID':25429, 'S': s, 'H': h}
#response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json = mes)
#print(response.json())

###########DELETE LONG TERM KEY
# If you lost your long term key, you can reset it yourself with below code.

# First you need to send a request to delete it. 
#mes = {'ID': 25429}
#response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json = mes)

#Then server will send a verification code to your email. 
#Send this code to server using below code

#mes = {'ID': 25429, 'CODE':945168}
#response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)

#Now your long term key is deleted. You can register again.