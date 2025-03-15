##!/usr/bin/env python3
#20250123
#from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import datetime 
import oqs
from collections import Counter
import math
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
def create_AES_cipher(kem, public_key, key_size):
    ciphertext, shared_secret = kem.encap_secret(public_key)
    aes_key = shared_secret[:key_size]  # Adjust based on AES key size (16 for AES-128)
    #iv = os.urandom(16)  # Initialization vector for AES
    return aes_key
def AES_encrypt(key, iv, message):
    cipher = AES.new(key, AES.MODE_GCM, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ciphertext
def calculate_entropy(data):
    flattened_data = []

    for item in data:
        if isinstance(item, bytes):
            flattened_data.extend(item)  # Append each byte as an integer
        elif isinstance(item, str):
            flattened_data.extend(item.encode("utf-8"))  # Encode string and append bytes as integers
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

# Main()
if __name__ == "__main__":
    # AES-256 key (32 bytes)
    aes_key_size=32
    algorithms=[ 'BIKE-L3', 'Kyber1024','Classic-McEliece-6960119']
    messages = ["REQUEST CLIMB TO FL100" , "CMPLY", "REQUEST CLIMB TO FL200","CMPLY", "REQUEST CLIMB TO FL300", "REQUEST CLIMB TO FL350", "CMPLY"]
    ciphertexts=[]
    entropy_list=[[0],[0],[0]]# long as the number of algorithms    
    f=open("/home/spal/update-1/stats.csv","w")    
    f.write(f"\n Entropy {datetime.datetime.now()} \nAlg./Messag.,")
    times=1
    for i in range(len(messages)):
        f.write(f"m{i+1},")
    for j in range(len(algorithms)):
      kem = oqs.KeyEncapsulation(algorithms[j])
      public_key = kem.generate_keypair()
      aes_key=create_AES_cipher(kem, public_key, aes_key_size)
      f.write(f"\n{algorithms[j]}:,")
      for msg in messages:
          entropy=0
          for _ in range(times):
             iv = os.urandom(16)  # Initialization vector for AES
             ciphertexts.append(AES_encrypt(aes_key, iv, msg))
             entropy += calculate_entropy(ciphertexts)
          entropy=entropy/float(times)
          entropy_list[j].append(entropy)
          f.write(f"{entropy},")
      ciphertexts.clear()

          #print(ciphertexts)
          #print(f"For oqs {algorithms[i]} Entropy of Ciphertext: {entropy:.4f} bits/byte")
    f.close()
    
    #Plot
    x = [1, 2, 3, 4, 5, 6, 7]  
    y = entropy_list  
    '''
    plt.figure(figsize=(8, 5))
    for i, y_values in enumerate(y):
        plt.plot(x, y_values, marker='o', linestyle='-', label=f' {algorithms[i]}')
    plt.xticks(ticks=x)  # Set only integer ticks    
    #plt.title('AES-256-GCM entropy encrypting alike content, from the AS side, with the same key.', fontsize=16)
    plt.xlabel('Number of Messages', fontsize=12)
    plt.ylabel('Entropy', fontsize=12)
    # Add a legend and grid
    plt.legend()
    #plt.grid(True, linestyle='--', alpha=0.5)
    '''
    # Show the plot
    #plt.show()
