import math
import sympy
import random
import pandas as pd
import csv

"""
The following are helper functions that generate the set of Paillier keys.
"""
# Step 1: Generate 2 primes
def step1(max_prime=1000):
    # Initialize primes
    p,q = 3, 7 # 3 & 7 so they fail the first condition
    # First & second conditions are part of the key generation, third is to ensure that 
    #   in the encryption phase 0 <= m < n.
    while (math.gcd(p*q, (p-1)*(q-1)) != 1) or (p==q) or (p*q < 10):
        p, q = sympy.randprime(0,max_prime), sympy.randprime(0,max_prime)
    return p, q

# Step 2: Compute n and lambda
def step2(p,q, simple=True):
    n = p*q
    if simple:
        lambd = (p-1)*(q-1) # phi(n)
        return n, lambd
    lambd = math.lcm(p-1,q-1)
    return n, lambd

# Step 3: Obtain g from the group of comprimes with n^2
def step3(n, simple=True):
    if simple:
        return n+1
    group = [i for i in range(1, n**2) if math.gcd(i, n**2) == 1]
    return group[random.randint(1, len(group))]

# Step 4: Obtain mu if possible from the modulo inverse of the L function applied to g^lambda mod n^2
def step4(g, lambd, n, p, q, simple=True):
    if simple:
        try:
            return sympy.mod_inverse((p-1)*(q-1), n) % n
        except ValueError as e:
            return False
    try:
        glambda_mod_nsquared = pow(g, lambd, n**2)
        L_of_glambda = (glambda_mod_nsquared - 1) // n
        mu = sympy.mod_inverse(L_of_glambda, n)
        return mu % n
    except ValueError as e:
        return False
    

#####

class paillier_instance():
    def __init__(self, max_prime=1000, simple=True, verbose=False):
        """
        This is the tool for encryption and decryption at the disposal of the
        agent that has access to the private scores.

        Args:
            max_prime (int): Maximum value for the primes.
            simple (bool): Whether to use predefined values for g, lambda and mu
                or randomize them. The second option is more secure but can make
                the computation much harder.
            verbose (bool): Whether to show progress via print() calls or not.
        """
        if verbose:
            print("\nStarting key generation process")
        # Paillier key generation process
        self.mu = False
        while not self.mu:
            self.p, self.q = step1(max_prime)
            if verbose:
                print("Step 1: Generate p, q:", self.p, self.q)
            self.n, self.lambd = step2(self.p, self.q, simple=simple)
            if verbose:
                print("Step 2: Obtain n and lambda:", self.n, self.lambd)
            self.g = step3(self.n, simple=simple)
            if verbose:
                print("Step 3: Pick a random g value:", self.g)
            self.mu = step4(self.g, self.lambd, self.n, self.p, self.q, simple=simple)
            if verbose:
                if not self.mu:
                    print("Step 4 FAILED (no modular inverse). Restarting process...")
                else:
                    print("Step 4: Generate mu:", self.mu)
        
        # Initialize variables for the contents
        self.scores = [None]*4
        self.WEIGHTS = [5, 3, 1, 1] # Weight for exams, labs, quizzes and project, respectively
        self.c_list = self.scores.copy()
        self.weighted = self.scores.copy() # Intermediate step for the crunching number phase
        
        self.result = 0

        # Keys
        self.pub_key = (self.n, self.g)
        self.priv_key = (self.lambd, self.mu)

    def get_pub_key(self):
        return self.pub_key

    def get_c_list(self):
        return self.c_list

    def get_result(self):
        return self.result

    def encrypt(self, input, verbose=False):
        '''
        Read input either directly as a list or as a csv filename. Then encrypt and 
        return a list with [c1, c2, c3, c4].
        '''
        if verbose:
            print("\nStarting encryption")
        if isinstance(input, list) and len(input) == 4:
            self.scores = input
        elif isinstance(input, str) and input[-4:] == ".csv":
            with open(input, "r") as file:
                scores_str = list(csv.reader(input, delimiter=","))[0]
            self.scores = [int(x) for x in scores_str]
        else:
            raise Exception("Error: Incorrect input format")
        
        # Encrypt
        for i in range(len(self.scores)):
            # Generate r
            r = 0
            # Ensure random r and gcd(r,n) == 1
            while math.gcd(r, self.n) != 1:
                r = random.randint(1,self.n-1)
            # Apply encryption scheme
            ci = ((self.g**self.scores[i]) * (r**self.n)) % (self.n**2)
            self.c_list[i] = ci
        
        if verbose:
            print("Encrypted list:", self.c_list)
        
        return self.c_list
    
    def decrypt(self, c, verbose=False):
        """
        Decrypts an individual value c and returns its plaintext m
        """
        if verbose:
            print("\nStarting decryption")
        try:
            # Compute c^lambda mod n^2
            clambda_mod_nsquared = pow(c, self.lambd, self.n**2)
            # Apply L function, L(x) = (x - 1) // n
            L_of_clambda = (clambda_mod_nsquared - 1) // self.n
            # Compute the plaintext message m = L(c^lambda mod n^2) * mu mod n
            self.result = (L_of_clambda * self.mu) % self.n
            
            return self.result

        except Exception as e:
            raise ValueError("Decryption failed. Ensure inputs are valid.") from e

def crunch(c_list, pub_key, over_10=False,verbose=False):
    """
    This function is meant to be used by the outsider agent.
    It performs the general encrypted score calculation from the partial encrypted scores.
    """
    if verbose:
        print("\nStarting number-crunching")

    n, g = pub_key
    WEIGHTS = [5, 3, 1, 1] # Weight for exams, labs, quizzes and project, respectively
    weighted = []
    
    # Step 1: Multiply each element by the corresponding weight
    #   following the equivalence: D(E(m,r)^k mod n^2) = k*m mod n
    for i in range(len(c_list)):
        weighted.append((c_list[i]**WEIGHTS[i]) % (n**2))
    if verbose:
        print("Results of multiplication:", weighted)

    # Step 2: Add all elements
    #   following the equivalence D(E(m1,r1)*E(m2,r2) mod n^2) = m1*m2 mod n
    c_result = (weighted[0] * weighted[1] * weighted[2] * weighted[3]) % n**2
    
    if verbose:
        print("Addition result:", c_result)

    if over_10:
        return round(c_result*0.1, 2)
    
    return c_result

    
if __name__ == "__main__":
    # Create an instance (generating the key pairs)
    a = paillier_instance(verbose=True)

    # Simulate the score list of a student
    score_list = [random.randint(0,10) for i in range(4)]
    #score_list = [10, 0, 10, 10]
    print("\nScore list:", score_list)

    # Encrypt the scores
    c_list = a.encrypt(score_list, verbose=True)

    # Homomorphic computations
    c_result = crunch(c_list, a.get_pub_key(), verbose=True)

    # Decrypt the result (and divide by 10 to obtain a score out of 10)
    res = a.decrypt(c_result)
    print(f"\nFinal score: {res*0.1:.2f}.")
