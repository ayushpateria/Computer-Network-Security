from Crypto.Util import number

#finding modular exponentiation using repeated squares
def modularExponentiation(base, exp, mod):
	res = 1
	while exp > 1:
		if exp & 1 == 0: # even
			base = base*base
			base %= mod
			exp /= 2
		else: #for odd
			res = base * res
			res %= mod
			base = base*base
			base %= mod
			exp = (exp-1) / 2
	return (res*base)%mod

# primes of the form 2*prime_q + 1 have a primitive root as 1 , 2 , prime_q, 2*prime_q

size = 2048
public_G = 2   # generator as 2 
public_P = (number.getPrime(size)*2)+1 #prime number of form 2*q+1
print "public_P : ", public_P

#private keys
alice_private = number.getPrime(size)
bob_private = number.getPrime(size)

#modularExponentiation key to send as message (G^private_key)%P
alice_message = modularExponentiation(public_G, alice_private, public_P)
bob_message = modularExponentiation(public_G, bob_private, public_P)
print "Alice sends ", alice_message, "to Bob"
print "Bob sends ", bob_message, "to Alice"

#modularExponentiation to decipher the full key to be used (message^key%P)
alice_key = modularExponentiation(alice_message, bob_private, public_P)
bob_key = modularExponentiation(bob_message, alice_private, public_P)

print "Bob decrypts and gets secret key as ", alice_key
print "Alice decrypts and gets secret key as ", bob_key
print "The keys are equal", (alice_key==bob_key)