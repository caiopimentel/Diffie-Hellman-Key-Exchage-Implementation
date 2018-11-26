#!/usr/bin/env python
#Non-compatible with Python 2

import hashlib
from binascii import hexlify

try:
    #Preferably using urandom (more secure)
    import os
    random_function = os.urandom
    random_provider = "OS random"
except (AttributeError, ImportError):
    import ssl
    random_function = ssl.RAND_bytes
    random_provider = "Python SSL"


class DiffieHellman():
    """
    Using standard primes from RFC 3526 MODP Groups 17 and 18. 
    Both are sufficient to generate AES 256 keys with a 540+ bit exponent.
    https://datatracker.ietf.org/doc/rfc3526/
    """

    def __init__ (self, generator = 2, group = 17, keyLenght=540):
        """
        Generate the public and private keys
        """
        
        #Lenght in bits
        min_keyLength = 180
        default_keyLength = 540

        default_generator = 2
        valid_generators = [2, 3, 5, 7, 11] #Must be primes. Some are not passing on the Legendre Symbol, why?

        # Sanity check for generator, group and keyLength
        if (generator not in valid_generators):
            print ("Error: Invalid generator. Default (2) will be used instead.")
            self.generator = default_generator
        else:
            self.generator = generator

        # Sanity check for keyLength
        if (keyLenght < min_keyLength):
            print ("Error: keyLenght is too small. Setting to minimum (",min_keyLength,").")
            self.keyLenght = min_keyLength
        else:
            self.keyLenght = keyLenght

        #Getting prime
        self.prime = self.getPrime(group)

        #Generating Keys
        self.privateKey = self.generatePrivateKey(self.keyLenght)
        self.publicKey = self.generatePublicKey()

    def getPrime(self, group = 17):
        """
        Returns the correspondent prime.
        To explore more primes: https://github.com/RedHatProductSecurity/Diffie-Hellman-Primes
        """

        default_group = 17

        primes = {
            17: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
            18: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
        }

        if group in primes.keys():
            return primes[group]
        else:
            print("Error: No prime with group",group,"Using default,",default_group,".")
            return primes[default_group]

    def generateRandomNumber(self, bits):
        """
        Generate a random number with the specified number of bits
        (https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator)
        """

        _rand = 0
        _bytes = bits // 8 + 8

        while (_rand.bit_length() < bits):
            _rand = int.from_bytes(random_function(_bytes), byteorder='big')
        
        return _rand

    def generatePrivateKey(self, bits):
        """
        Generate the private key
        """

        return self.generateRandomNumber(bits)

    def generatePublicKey(self):
        """
        Generate public key with generator ** privateKey % prime
        """
        return pow(self.generator, self.privateKey, self.prime)

    def testReceiverPublicKey (self, receiverPublicKey):
        """
        Checks receiver Public Key to make sure it's valid.
        Since a safe prime is used, verify that the Euler's Criterion for the Legendre Symbol == 1
        Not super trustworthy tho, it has its limitations.
        (https://en.wikipedia.org/wiki/Legendre_symbol) (https://www.youtube.com/watch?v=o23itWTcEYw)
        """

        if (receiverPublicKey > 2 and receiverPublicKey < self.prime - 1):
            if(pow(receiverPublicKey, (self.prime - 1)//2, self.prime) == 1):
                #if it's a quadratic residue
                return True
        return False

    def generateSharedSecret(self, privateKey, receiverPublicKey):
        """
        Generates the shared secret after checking if receiverPublicKey is valid.
        """

        if (self.testReceiverPublicKey(receiverPublicKey) == True):
            sharedSecret = pow (receiverPublicKey, privateKey, self.prime)
            return sharedSecret
        else:
            raise Exception ("Invalid public key.")

    def generateSharedKey (self, receiverPublicKey):
        """
        Gets shared secret, then hash it to obtain the shared key.
        """

        self.sharedSecret = self.generateSharedSecret(self.privateKey, receiverPublicKey)

        try:
            _sharedSecretBytes = self.sharedSecret.to_bytes(self.sharedSecret.bit_length() // 8 + 1, byteorder="big")
        except AttributeError:
            _sharedSecretBytes = str(self.sharedSecret)

        shared = hashlib.sha256()
        shared.update(bytes(_sharedSecretBytes))
        self.key = shared.digest()

    def getSharedKey (self):
        """
        Return shared secret Key
        """
        return self.key

    def displayParameters (self):
        """
        Display parameters used on the DH agreement.
        """

        print(">>>>>>> Parameters:")
        print("Prime[{0}]: {1}\n".format(self.prime.bit_length(), self.prime))
        print("Generator:", self.generator, "\n")
        print("Private Key[{0} bits]: {1}\n".format(self.privateKey.bit_length(), self.privateKey))
        print("Public Key[{0} bits]: {1}\n".format(self.publicKey.bit_length(), self.publicKey))

    def displayShared (self):
        """
        Display the results of the exchange.
        """
        print(">>>>>>> Results:")
        print("Shared Secret[{0}]: {1}\n".format(self.sharedSecret.bit_length(), self.sharedSecret))
        print("Shared Key [{0}]: {1}\n".format(len(self.key), hexlify(self.key)))


if __name__ == "__main__":
    """
    Test Diffie-Hellman exchange.
    """

    alice = DiffieHellman(2,17,670)
    bob = DiffieHellman(2,17,540)

    alice.generateSharedKey(bob.publicKey)
    bob.generateSharedKey(alice.publicKey)

    print ("\n============= ALICE:\n")
    alice.displayParameters()
    alice.displayShared()
    print("\n")
    
    print ("\n============= BOB:\n")
    bob.displayParameters()
    bob.displayShared()
    print("\n")

    print("============= EXCHANGE RESULT:")
    if (alice.getSharedKey() == bob.getSharedKey()):
        print("Shared keys match!!!")
        print("Key:", hexlify(alice.key))
    else:
        print("Shared keys didn't match...")
        print("\nAlice's Shared Secret:", alice.generateSharedSecret(alice.privateKey,bob.publicKey))
        print("\nBob's Shared Secret:", bob.generateSharedSecret(bob.privateKey,alice.publicKey))
    print("\n")