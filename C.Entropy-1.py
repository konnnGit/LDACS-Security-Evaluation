##!/usr/bin/env python3
#20250123
#from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import numpy as np
import datetime
import oqs
from collections import Counter
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
def create_AES_cipher(key, iv):
    cipher = AES.new(key, AES.MODE_GCM, iv)
    return cipher
def create_AES_key(the_kem):
    kem = oqs.KeyEncapsulation(the_kem)
    public_key = kem.generate_keypair()
    _, shared_secret = kem.encap_secret(public_key)
    return shared_secret[:32] #32 bytes for 256-bit key
def calculate_entropy(data):
    flattened_data = []
    for item in data:
        if isinstance(item, bytes):
            flattened_data.extend(item)  # Append each byte as an integer
        elif isinstance(item, str):
            flattened_data.extend(item.encode("utf-8"))# Encode string and append bytes as integers
        elif isinstance(item, int):  # If item is already an integer
            flattened_data.append(item)
        else:
            raise ValueError("Unsupported data type: must be str, bytes, or int")
    #print (flattened_data)
    # Count the frequency of each integer byte
    freq = Counter(flattened_data)
    total = len(flattened_data)

    # Calculate entropy using the formula: -Σ(p * log2(p))
    entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
    return entropy/8.0000

#---------- Main()-------------------

algorithms=[  'Kyber768','BIKE-L3','Classic-McEliece-6960119']

m = ["REQUEST CLIMB TO FL100" , "CLIMB TO AND MAINTAIN FL100", "ROGER", "REQUEST CLIMB TO FL200","REQUEST VOICE CONTACT", "ROGER", "REQUEST CLIMB TO FL320","CLIMB TO AND MAINTAIN FL320", "REQUEST CLIMB TO FL350", "CLIMB TO AND MAINTAIN FL350","REQUEST DIRECT TO [position]" ,"CLEARED [position]","WHEN ABLE PROCEED DIRECT TO [position]","RADAR SERVICES TERMINATED" ,"SERVICE UNAVAILABLE"  , "CONFIRM ASSIGNED ALTITUDE" , "ROGER", "REQUEST DESCENT TO FL200","DESCENT TO AND MAINTAIN FL200", "REQUEST DESCENT TO FL100","DESCENT TO AND MAINTAIN FL100","HOLD AT [position] MAINTAIN [altitude] INBOUND TRACK [degrees] [direction] TURNS [leg type ]" ,"REPORT BACK ON ROUTE"]
messages=1*m
ciphertext=''
entropy=0
entropies=ciphertexts=[]
for a in range(len(algorithms)):
    entropies.append([])
    ciphertexts.append([])
    
f=open("/home/spal/update-1/C.stats.csv","w")
f.write(f"\n Entropy eval. ({datetime.datetime.now()}).\n")

temp_key=os.urandom(32)
temp_iv = os.urandom(16)
global_aes=create_AES_cipher(temp_key, temp_iv)

for i in range(len(messages)):
    f.write(f",m{i+1}")
for al in range(len(algorithms)):
    aes_key=create_AES_key(algorithms[al])
    f.write(f"\n{algorithms[al]}:,")
    for m in range(len(messages)):
        iv = os.urandom(16)#new iv for each messagge 
        ciphertext=global_aes.encrypt(pad(messages[m].encode(), AES.block_size))  
        ciphertexts[al]+=ciphertext
        entropy=(calculate_entropy(ciphertexts[al]))
        f.write(f"{entropy},")
f.close()

