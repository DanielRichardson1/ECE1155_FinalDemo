from hashlib import sha256
from ecdsa.ecdsa import generator_256, Public_key, Private_key
import random
from Crypto.Util.number import bytes_to_long

'''
This code simulates an implementation vulnerability in Elliptic Curve Cryptography often known as 'Sony's Problem'
The vulnerability results from the reuse of the same random value on the elliptic curve for multiple signatures
'''

g = generator_256
n = g.order()

# this is the actual private key of the signer
private_key = random.randrange(1, n)

public_key = Public_key(g, g * private_key)
private_key_object = Private_key(public_key, private_key)

# k must be in the range 1 to n, the order of the curve
# k is the random generator (not so random here)
k = random.randrange(1, n)

m1 = 'this is my first secret message'
m2 = 'the second secret message is this string'

# manually generate the hashes of the messages to use them 
hash_m1 = bytes_to_long(sha256(m1.encode()).digest())
hash_m2 = bytes_to_long(sha256(m2.encode()).digest())

# sign both messages with the same nonce
# the signature is composed of r, the x coordinate of the random point on the EC, and s, the signature itself
# s = k^-1 * (hash_m1 + r*private_key) mod n
s1 = private_key_object.sign(hash_m1, k)
s2 = private_key_object.sign(hash_m2, k)

# now we need to obtain k from the two signatures using the formula:
# k = ((hash_m1 - hash_m2)/(s1.s - s2.s)) mod n
# to do this, we have to calculate the multiplicative inverse
k_derived = (hash_m1 - hash_m2)*pow((s1.s - s2.s), -1, n) % n 

assert k_derived == k

# Now we can derive the secret key
private_key_derived = pow(s1.r, -1, n) * (s1.s*k_derived - hash_m1) % n

assert private_key_derived == private_key




