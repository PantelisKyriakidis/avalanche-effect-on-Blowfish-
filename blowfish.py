from Crypto.Cipher import Blowfish
from Crypto import Random
import random


def bitstring_to_bytes(x):
    s = ''.join(str(e) for e in x)
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')


def differentBits(x, y):
    # convert Bytes to bits, Add zeros for len()=64 and split them
    x = (bin(int.from_bytes(x, byteorder="big"))[2:])
    y = (bin(int.from_bytes(y, byteorder="big"))[2:])
    x = list((64 - len(x)) * str(0) + x)
    y = list((64 - len(y)) * str(0) + y)
    counter = 0
    for i in range(0, 64):
        if (x[i] != y[i]):
            counter += 1
    return counter


def changeBit(y, i):
    if (y[i] == 1):
        y[i] = 0
    else:
        y[i] = 1


# ...................................MAIN...........................................
counterEcb = 0
counterCbc = 0
for j in range(35):
    x = []
    for i in range(0, 64):
        x.append(random.randint(0, 1))

    y = x.copy()
    randIndex = random.randint(0, 63)
    changeBit(y, randIndex)

    xBytes = bitstring_to_bytes(x)
    yBytes = bitstring_to_bytes(y)
    # print('msg1= %s\nmsg2= %s\n\n'%(xBytes,yBytes))


    # ...............................ECB MODE.....................................
    key = b'This is my key for today'
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    xEnc = cipher.encrypt(xBytes)
    yEnc = cipher.encrypt(yBytes)

    '''#testing for correct encryption
    xDec=cipher.decrypt(xEnc)
    print("checking if encryption in ecb mode works correctly:")
    print('msg: %s'%xBytes)
    print('decrypted msg: %s \n\n'%xDec)
      '''
    # how many different bits we got
    counterEcb += differentBits(xEnc, yEnc) / 64

    # ............................................CBC MODE.......................................
    bs = Blowfish.block_size
    key = b'This is my key for today'
    iv = Random.new().read(bs)
    ciphercbc = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    xEnc = iv + ciphercbc.encrypt(xBytes)
    yEnc = iv + ciphercbc.encrypt(yBytes)

    '''#testing for correct encryption
    xDec=ciphercbc.decrypt(xEnc)
    print("checking if encryption in cbc mode works correctly:")
    print('msg: %s'%xBytes)
    print('decrypted msg: %s \n\n'%xDec)
    '''

    # how many different bits we got
    counterCbc += differentBits(xEnc, yEnc) / 64

print("ECB MODE avg of difference in bits: %s" % (counterEcb / 35.0))
print("CBC MODE avg of difference in bits: %s" % (counterCbc / 35.0))
