#!/usr/bin/python

import sys, getopt, hashlib
from mnemonic import Mnemonic
from binascii import hexlify, unhexlify

mnemonic = Mnemonic('english')

# Encodes the specified binary data as a BIP39 mnemonic string
def encode(binary_data):
    try:
        mnemonic_string = mnemonic.to_mnemonic(binary_data)
        return mnemonic_string
    except:
        print('Error encoding data')
        sys.exit(2)

# Decodes the specified mnemonic string as binary data
def decode(mnemonic_string):
    mnemonic_list = mnemonic_string.split()
    if len(mnemonic_list) % 3 > 0:
        raise Exception("Unexpected length of mnemonic sentence")
    try:
        idx = map(lambda x: bin(mnemonic.wordlist.index(x))[2:].zfill(11), mnemonic_list)
        b = ''.join(idx)
    except:
        raise Exception("Unable to map mnemonic word")
    l = len(b)
    d = b[:l // 33 * 32]
    h = b[-l // 33:]
    nd = unhexlify(hex(int(d, 2))[2:].rstrip('L').zfill(l // 33 * 8))
    nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[:l // 33]
    if (nh==h):
        return nd
    else:
        raise Exception("Mnemonic sentence does not match checksum")

# Converts the specified mnemonic to a seed
def to_seed(mnemonic_string, passphrase = ''):
    return mnemonic.to_seed(mnemonic_string, passphrase)

def main(argv):
    hexdata = ''
    mnemonic = ''
    try:
        opts, args = getopt.getopt(argv,"heds",["encode=","decode="])
    except getopt.GetoptError:
        print('To encode hex into a mnemonic: bip39.py -e <hexstring>')
        print('or')
        print('To decode a mnemonic into hex: bip39.py -d <mnemonic words>')
        print('or')
        print('To create a seed from a mnemonic: bip39.py -s <mnemonic words>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('To encode hex into a mnemonic: bip39.py -e <hexstring>')
            print('or')
            print('To decode a mnemonic into hex: bip39.py -d <mnemonic words>')
            print('or')
            print('To create a seed from a mnemonic: bip39.py -s <mnemonic words>')
            sys.exit()
        elif opt in ("-e", "--encode"):
            # Read hex data from command line argument
            hexdata = args[0]

            # Convert hex data to binary data
            binary_data = unhexlify(hexdata)

            # Encode binary data to BIP39 mnemonic
            print(encode(binary_data))
        elif opt in ("-d", "--decode"):
            # Read mnemonic string from arguments
            mnemonic_string = ' '.join(args)

            # Decode mnemonic string into binary data
            binary_data = decode(mnemonic_string)

            # Encode binary data as a hex string
            print(hexlify(binary_data))
        elif opt in ("-s", "--seed"):
            # Read mnemonic string from arguments
            mnemonic_string = ' '.join(args)

            # Read password from the command line
            #print "Enter a passphrase for this seed: "
            #passphrase = sys.stdin.readline().rstrip()
            passphrase = ""

            # Convert the mnemonic string into a seed
            binary_data = to_seed(mnemonic_string, passphrase)

            # Convert the binary data into a hex string
            hex_string = hexlify(binary_data)

            print(hex_string)

    #print 'Hex data is %s.' % hexdata
    #print 'Mnemonic words are %s.' % " ".join(mnemonic)

if __name__ == "__main__":
    main(sys.argv[1:])