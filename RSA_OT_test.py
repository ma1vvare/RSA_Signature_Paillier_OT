import hashlib
from paillier.paillier import *
import random
import sys
import math
import os
import M2Crypto


def convertStr(s):
  """Convert string to either int or float."""
  try:
    ret = int(s)
  except ValueError:
    # Try float.
    ret = float(s)
  return ret


def empty_callback():
  return
#-----------------RSA signature--------------------------
M2Crypto.Rand.rand_seed(os.urandom(400))
print "Generating a 1024 bit private/public key pair for Bob..."
Bob = M2Crypto.RSA.gen_key(400, 65537)
Bob.save_key('Bob-private.pem', None)
Bob.save_pub_key('Bob-public.pem')

message = "This is the ballot signature signed by AS"
SignKey = M2Crypto.EVP.load_key('Bob-private.pem')
SignKey.sign_init()
hashMsg = hashlib.sha256(message).hexdigest()
SignKey.sign_update(hashMsg)
SignResult = SignKey.sign_final()
print "SignResult:", SignResult
print "hashMsg:", hashMsg
print "inthashMsg : ", int(hashMsg, 16)
# print "intSignResult : ", int(SignResult)
print "hexhashMsg : ", hex(int(hashMsg, 16))[2:]

# Represent signature with hex
SigResultHex = SignResult.encode('hex')
print "SignResultHex:", SigResultHex
# Represent signature with decimal
SigResultInt = int(SignResult.encode('hex'), 16)
print "intSignResult : ", SigResultInt


#-----------------Paillier homomorphic--------------------------
VerifyKey = M2Crypto.RSA.load_pub_key('Bob-public.pem')
print "VerifyKey.n :", VerifyKey.n, " ", type(VerifyKey.n)
NInt = int(VerifyKey.n.encode('hex'), 16)
print "NInt :", NInt
print "Generating Paillier keypair..."
priv, pub = generate_keypair(512)
print "Paillier pub.n :", pub.n
lamb = input("Enter the number of ballot signature you want: ")
# encrypt the ballot signature number lambda which voter's pick
# by paillier homomophic encryption
crypt_lamb = encrypt(pub, int(lamb))

'''
crypt_4 = encrypt(pub, 4)  # 5-4=1
inver4 = modinv(crypt_4, pub.n_sq)  # cipher inverse, E(4)^-1
inverlam = modinv(crypt_lamb, pub.n_sq)

# if lamb < number , then minus pub.n is answer
# print "ans0 : ", decrypt(priv, pub, crypt_lamb * inver4) - pub.n
print "ans0 : ", decrypt(priv, pub, crypt_lamb * inver4)
# print "anslamb : ", decrypt(priv, pub, crypt_lamb)


ans = decrypt(priv, pub, crypt_lamb * inver4)
print "after minus :", ans
'''
lam_list = []
#randomNum = 101
for lam in range(1, 6):
  crypt_lam = encrypt(pub, int(lam))
  crypt_inv_lam = modinv(crypt_lam, pub.n_sq)  # cipher inverse, E(lam)^-1
  cipher_tmp = e_add(pub, crypt_lamb * crypt_inv_lam, crypt_ballot_Sig)
  ans = decrypt(priv, pub, cipher_tmp)
  print lam, ". ans : ", ans
  #-----------------RSA signature verify--------------------------
  hexSigRecover = hex(ans)  # covert int(ans_sig) to hex(ans_sig)
  hexSigRecover = hexSigRecover[2:-1]  # remove 0x and L
  print "hexSigRecover : ", hexSigRecover
  VerifyKey = M2Crypto.RSA.load_pub_key('Bob-public.pem')
  VerifyEVP = M2Crypto.EVP.PKey()
  VerifyEVP.assign_rsa(VerifyKey)
  VerifyEVP.verify_init()
  # Voter can use "hexSigRecover" to recover original ballot signature
  OrigSigRecover = hexSigRecover.decode('hex')
  print "OrigSigRecover : ", OrigSigRecover
  # hashMsg will be calculate by voter after obtaining message and signature
  VerifyEVP.verify_update(hashMsg)
  if VerifyEVP.verify_final(OrigSigRecover):
    print "The ballot signature was successfully verified."
  else:
    print "The ballot signature was NOT verified!"

  lam_list.append(ans)
  # print lam_list
# print lam_list
'''
#-----------------RSA signature verify--------------------------
VerifyKey = M2Crypto.RSA.load_pub_key('Bob-public.pem')
VerifyEVP = M2Crypto.EVP.PKey()
VerifyEVP.assign_rsa(VerifyKey)
VerifyEVP.verify_init()
# hashMsg will be calculate by voter after obtaining message and signature
VerifyEVP.verify_update(hashMsg)
if VerifyEVP.verify_final(SignResult) == 1:
  print "The string was successfully verified."
else:
  print "The string was NOT verified!"
'''
