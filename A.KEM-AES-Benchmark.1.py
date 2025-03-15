

import oqs
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import time
import matplotlib.pyplot as plt
import numpy as np

def kem_work(algorithm):
    # Initialize key encapsulation mechanism (KEM)
    kem = oqs.KeyEncapsulation(algorithm)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return kem,  public_key

def create_AES_cipher(kem, public_key, key_size):
    ciphertext, shared_secret = kem.encap_secret(public_key)
    # Use shared secret as key for AES encryption
    aes_key = shared_secret[:key_size]
    iv = os.urandom(16)  # Initialization vector for AES, 16 bytes
    return aes_key,iv

def AES_encrypt(key, iv, message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return ciphertext
def AES_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    return decrypted_message
def run_main(iterations, algorithms, message, aes_key_size):
    avg_kem_time=[]
    avg_aes_time=[]
    for t in range(len(algorithms)):
        avg_kem_time.append(0)
        avg_aes_time.append(0)
    for i in range(iterations):
        for j  in range(len(algorithms)):
            start = time.time()
            kem,public_key=kem_work(algorithms[j])
            stop = time.time()
            avg_kem_time[j]+=stop-start
            start = time.time()
            key,iv=create_AES_cipher(kem,public_key,aes_key_size)
            ciphertext = AES_encrypt(key, iv, message)
            decrypted_message = AES_decrypt(key, iv, ciphertext)
            stop = time.time()
            avg_aes_time[j]+=stop-start
    for k in range(len(algorithms)):
        avg_kem_time[k]=avg_kem_time[k]/iterations
        avg_aes_time[k]=avg_aes_time[k]/iterations
    return avg_kem_time,avg_aes_time
def the_plot(categories, group1,group2):
    # Bar settings
    x = np.arange(len(categories))  # x locations for categories
    width = 0.2  # Bar width
    # Create the bars
    fig, ax = plt.subplots()
    bars1 = ax.bar(x - width/2, group1, width, label='NIST Security Level 3', color='skyblue')
    bars2 = ax.bar(x + width/2, group2, width, label='NIST Security Level 5', color='blue')

    # Add labels, title, and legend
    ax.set_xlabel('Algorithm')
    ax.set_ylabel('Time')
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend()

    # Show the plot
    plt.tight_layout()
    plt.show()
#-------main()-----------------------------
print ("Start...")
algorithmsL3=['BIKE-L3','Kyber768','Classic-McEliece-460896' ]
algorithmsL5=['BIKE-L5','Kyber1024', 'Classic-McEliece-6960119' ]
cateories=['BIKE','Kyber', 'Classic-MCEliece' ]
message = "REQUEST TO CLIMB IN FL350"
aes_key_size=32 #32 bytes for 256 key
iterations=3
f=open("/home/spal/LDACS/stats.csv", "a")
groupKEML3, groupAESL3=run_main(iterations,algorithmsL3, message, aes_key_size)
f.write(f"\nAlgorithm L-3 ,KEM_time, AES_time=f(KEM)\n")
for i in range(len(algorithmsL3)):
    f.write(f"{str(algorithmsL3[i])}, {str(groupKEML3[i])}, {str(groupAESL3[i])}\n")
#print (f"For KEM {algorithmsL3}, execution time  {groupKEML3}")
groupKEML5, groupAESL5=run_main(iterations,algorithmsL5, message, aes_key_size)
f.write(f"\nAlgorithm L-5 ,KEM_time, AES_time=f(KEM)\n")
for i in range(len(algorithmsL5)):
    f.write(f"{str(algorithmsL5[i])}, {str(groupKEML5[i])}, {str(groupAESL5[i])}\n")
#print (f"For KEM {algorithmsL5}, execution time  {groupKEML5}")
#the_plot(cateories, groupKEML3,groupKEML5)
#the_plot(cateories, groupAESL3,groupAESL5)
f.close()
print ("Finish")





