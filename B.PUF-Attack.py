import numpy as np
import cma
import time

# Function to generate reverse PUF data
def generate_reverse_puf_data(num_challenges, num_bits, noise_level):    
    # Randomly generate challenges and stable PUF responses
    challenges = np.random.randint(0, 2, size=(num_challenges, num_bits))
    stable_responses = np.random.randint(0, 2, size=(num_challenges, response_bits))
    # Introduce noise to responses
    noise = np.random.rand(num_challenges, response_bits) < noise_level
    noisy_responses = np.bitwise_xor(stable_responses, noise.astype(int))
    return challenges, noisy_responses

# Generate synthetic SRAM PUF data
num_challenges = 100  
num_bits = 32          # Number of bits in each challenge
response_bits = 168
noise_level = 0.05     # Noise level
challenges, responses = generate_reverse_puf_data(num_challenges, num_bits, noise_level)

# Split data into training and testing sets
split_ratio = 0.8
num_train = int(split_ratio * num_challenges)

responses_train = responses[:num_train]
challenges_train = challenges[:num_train]
responses_test = responses[num_train:]
challenges_test = challenges[num_train:]

# Define the objective function for CMA-ES
def cma_objective(candidate, response, target_challenge):
    # Convert candidate to binary (threshold at 0.5)
    candidate_binary = (candidate > 0.5).astype(int)
    # Compute error as Hamming distance between candidate and target challenge
    error = np.sum(candidate_binary != target_challenge)
    return error
t1=time.time()
# Run CMA-ES for each test response
predicted_challenges = []
for i, response in enumerate(responses_test):
    # Extract the true challenge for comparison
    true_challenge = challenges_test[i]
    # Define the initial guess (random values) and step size
    initial_guess = np.random.rand(num_bits)
    step_size = 0.3

    # Run CMA-ES optimization
    es = cma.CMAEvolutionStrategy(initial_guess, step_size)
    es.optimize(lambda x: cma_objective(x, response, true_challenge), iterations=100)

    # Get the best solution from CMA-ES
    best_candidate = es.result.xbest
    predicted_challenges.append((best_candidate > 0.5).astype(int))

# Evaluate prediction accuracy

predicted_challenges = np.array(predicted_challenges)
t2=time.time()
accuracy = np.mean(predicted_challenges == challenges_test)
print(f"Overall Prediction Accuracy: {accuracy:.2%} in {t2-t1} seconds.")
