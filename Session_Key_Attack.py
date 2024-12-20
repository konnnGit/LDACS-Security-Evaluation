from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# Encrypt a plaintext with a given key and random IV
def encrypt_message(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

# Generate a dataset with variability
def generate_dataset(size, keys, plaintexts):
    features = []
    labels = []
    for _ in range(size):
        key = np.random.choice(keys)  # Randomly select a key
        plaintext = np.random.choice(plaintexts)  # Randomly select a plaintext
        ciphertext = encrypt_message(key, plaintext)
        features.append(list(ciphertext[:16]))  # Use the first 16 bytes as features
        labels.append(hash(key) % 10)  # Group labels by key hash
    return features, labels

# Parameters
keys = [get_random_bytes(16) for _ in range(2)]  # 5 random keys
plaintexts = [b"REQUEST CLIMB TO FL370", b"UNABLE DUE TO TRAFFIC",  b"CLIMB TO AND MAINTAIN FL270", b"REPORT LEVEL FL270",b"REQUEST DIVE TO FL200",  b"DIVE TO AND MAINTAIN FL200"]  # 4 plaintexts

# Generate dataset
features, labels = generate_dataset(50, keys, plaintexts)
#print (features, labels)
# Train-test split
X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.2, random_state=42)

# Train Random Forest model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Predict and evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print("Random Forest Accuracy:", accuracy)


nn_model = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500)
nn_model.fit(X_train, y_train)
y_pred_nn = nn_model.predict(X_test)
print("Neural Network Accuracy:", accuracy_score(y_test, y_pred_nn))



#svm_model = SVC(kernel='rbf')
#svm_model.fit(X_train, y_train)
#y_pred_svm = svm_model.predict(X_test)
#print("SVM Accuracy:", accuracy_score(y_test, y_pred_svm))
