# Python3 implementation for RC4 algorithm
# References: https://en.wikipedia.org/wiki/RC4#Description

import codecs   #This library is used to convert hex bytes to unicode

"""
These first 3 functions are used for conversions.
"""

def hexToBin(hexS):   #Changes a string of hex to string of bin
    binS = ""
    hexS = str(hexS)    #Make sure it is a string
    length=len(hexS)
    for i in range (0,length):
        if hexS[i] == "0":
            binS += "0000"
        elif hexS[i] == "1":
            binS += "0001"
        elif hexS[i] == "2":
            binS += "0010"
        elif hexS[i] == "3":
            binS += "0011"
        elif hexS[i] == "4":
            binS += "0100"
        elif hexS[i] == "5":
            binS += "0101"
        elif hexS[i] == "6":
            binS +="0110"
        elif hexS[i] == "7":
            binS += "0111"
        elif hexS[i] == "8":
            binS += "1000"
        elif hexS[i] == "9":
            binS += "1001"
        elif hexS[i] == "A" or hexS[i] == "a":
            binS += "1010"
        elif hexS[i] == "B" or hexS[i] == "b":
            binS += "1011"
        elif hexS[i] == "C" or hexS[i] == "c":
            binS += "1100"
        elif hexS[i] == "D" or hexS[i] == "d":
            binS += "1101"
        elif hexS[i] == "E" or hexS[i] == "e":
            binS += "1110"
        elif hexS[i] == "F" or hexS[i] == "f":
            binS += "1111"
        else:
            print("Error in HexToBin conversion!")
            return binS
    return binS

def binToHex(binS):    #Changes a string of bin to string of hex
    hexaS = ""
    binS = str(binS)    #Make sure it is a string
    length = len(binS)
    if length%4!=0:
        if length%4==1: #We should add 3 zeros to the left to make the binary string complete (to the nearest half-byte needed in hex)
            binS="000" + binS
        elif length%4==2:
            binS="00" + binS
        elif length%4==3:
            binS="0" + binS
    length = len(binS)
    for i in range (0,length,4):
        temp = binS[i]+binS[i+1]+binS[i+2]+binS[i+3]
        if temp =="0000":
            hexaS+="0"
        elif temp == "0001":
            hexaS+="1"
        elif temp == "0010":
            hexaS+="2"
        elif temp == "0011":
            hexaS+="3"
        elif temp == "0100":
            hexaS+="4"
        elif temp == "0101":
            hexaS+="5"
        elif temp == "0110":
            hexaS+="6"
        elif temp == "0111":
            hexaS+="7"
        elif temp == "1000":
            hexaS+="8"
        elif temp == "1001":
            hexaS+="9"
        elif temp == "1010":
            hexaS+="A"
        elif temp == "1011":
            hexaS+="B"
        elif temp == "1100":
            hexaS+="C"
        elif temp == "1101":
            hexaS+="D"
        elif temp == "1110":
            hexaS+="E"
        elif temp == "1111":
            hexaS+="F"
        else:
            print("Error in BinToHex conversion!")
            return hexaS
    return hexaS

def textToHex(text):
    hexaS = ""
    text = str(text)
    length = len(text)

    for i in range(0,length):
        ch = text[i]         #Take each char from string
        asciiVal = ord(ch)   #Find its ascii integer value
        asciiHex = hex(asciiVal).lstrip("0x").rstrip("L")    #Change ascii integer to hexadecimal value
        hexaS += asciiHex

    return hexaS


"""
Here starts the RC4 Implementation.
First, the functions to generate a keystream: 1.KSA 2.PRGA
    1. A permutation of all 256 possible bytes (denoted "S" below).
    2. Two 8-bit index-pointers (denoted "i" and "j").
"""

def KSA(key):   #Used to initialize the permutation in the array S
    '''
    Key Scheduling Algorithm:
        - keyLength is defined as the number of bytes in the key (1 ≤ keyLength ≤ 256)
        - The array S is initialized to the identity permutation
        - S is then processed for 256 iterations in a similar way to the main PRGA,
          but also mix-in bytes of the key at the same time.
    '''
    keyLength = len(key)
    S = list(range(256))  #Creates the array S = [0,1,2, ... , 255]
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keyLength]) % 256
        S[i], S[j] = S[j], S[i]  #Swap values

    return S


def PRGA(S):    #Modifies the state and outputs the keystream a byte at a time
    '''
    Pseudo-Random Generation Algorithm:
        - At each iteration: the PRGA increments i,
        - then adds the value of S pointed to by i to j,
        - exchanges the values of S[i] and S[j],
        - and finally outputs the element of S at the location S[i] + S[j] (modulo 256).
    '''
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  #Swap values

        K = S[(S[i] + S[j]) % 256]
        yield K

"""
And now, the logic behind encryption and decryption.
"""

def getKeystream(key):  #Takes the encryption key and gets the keystream
    S = KSA(key)
    return PRGA(S)


def RC4(key, text):   #RC4 XOR used to encrypt or decrypt
    '''
    Function takes in unicode key and Plain/Cipher text, generate keystream,
    XOR keystream and text, then outputs Cipher/Plain text as a Hex string
    '''
    keystream = getKeystream(key)

    hexList = []  #List of encoded or decoded text
    for word in text:
        val = ("%02X" % (word ^ next(keystream)))  #XOR 1 byte at a time and output in corrected hex
        hexList.append(val)     #Append value to list

    hexString = ''.join(hexList)     #Takes all items in list and joins them into one string
    return hexString


def main():

    print("----------------------------------------------------")
    print("Welcome to our RC4 Encryptor/Decryptor!")
    print("----------------------------------------------------")
    loop = 1
    while loop == 1:    #Creates a loop to always come back to the main menu
        print("Please choose 1 for Encryption, 2 for Decryption or 3 to Exit the program")
        choice = int(input("Enter your choice: "))

        if choice == 1: #Encryption
            print("----------------------------------------------------")
            print("You chose to encrypt a message.")
            print("Is your plaintext in: 1)binary, 2)hexadecimal or 3)regular text ?")
            messageChoice = int(input("Enter your choice: "))
            while messageChoice != 1 and messageChoice != 2 and messageChoice != 3:
                messageChoice = int(input("Error! Please enter a valid option: "))
            print("\nWhat about your key: 1)binary, 2)hexadecimal or 3)regular text ?")
            keyChoice = int(input("Enter your choice: "))
            while keyChoice != 1 and keyChoice != 2 and keyChoice != 3:
                keyChoice = int(input("Error! Please enter a valid option: "))
            print("----------------------------------------------------")

            if messageChoice == 1:        #Convert cipher from binary to unicode
                plaintext = str(input("Enter your plaintext: "))
                while len(plaintext) % 8 != 0:  #To convert to Unicode, plaintext must be multiple of a complete byte: since 8 bits make 1 byte
                    plaintext = str(input("Error! Your plaintext should correspond to full bytes. Please enter your plaintext again: "))

                #Now convert binary to hex
                plaintextHex = binToHex(plaintext)
                #Then hex to unicode
                plaintext = codecs.decode(plaintextHex, 'hex_codec')
                plaintext = [c for c in plaintext]

                if keyChoice == 1:    #Convert key from binary to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 8 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 8 bits make 1 byte
                        key = str(input("Error! Your key should correspond to full 8-bits bytes. Please enter your key again: "))

                    #First convert binary to hex
                    keyHex = binToHex(key)
                    #Then hex to unicode
                    key = codecs.decode(keyHex, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 2:  #Convert key from hex to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 2 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 2 hex character make 1 byte
                        key = str(input("Error! Your key should correspond to full 2-hex bytes. Please enter your key again: "))
                    key = codecs.decode(key, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 3:  #Convert key from text to unicode
                    key = str(input("Enter your key: "))
                    key = [ord(c) for c in key]


            elif messageChoice == 2:      #Convert message from hex to unicode
                plaintext = str(input("Enter your plaintext: "))
                while len(plaintext) % 2 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 2 hex characters make 1 byte
                    plaintext = str(input("Error! Your plaintext should correspond to full 2-hex bytes. Please enter your plaintext again: "))
                plaintext = codecs.decode(plaintext, 'hex_codec')
                plaintext = [c for c in plaintext]

                if keyChoice == 1:    #Convert key from binary to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 8 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 8 bits make 1 byte
                        key = str(input("Error! Your key should correspond to full 8-bits bytes. Please enter your key again: "))

                    #First convert binary to hex
                    keyHex = binToHex(key)
                    #Then hex to unicode
                    key = codecs.decode(keyHex, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 2:  #Convert key from hex to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 2 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 2 hex character make 1 byte
                        key = str(input("Error! Your key should correspond to full 2-hex bytes. Please enter your key again: "))
                    key = codecs.decode(key, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 3:  #Convert key from text to unicode
                    key = str(input("Enter your key: "))
                    key = [ord(c) for c in key]


            elif messageChoice == 3:      #Convert message from text to unicode
                plaintext = str(input("Enter your plaintext: "))
                plaintext = [ord(c) for c in plaintext]

                if keyChoice == 1:    #Convert key from binary to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 8 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 8 bits make 1 byte
                        key = str(input("Error! Your key should correspond to full 8-bits bytes. Please enter your key again: "))

                    #First convert binary to hex
                    keyHex = binToHex(key)
                    #Then hex to unicode
                    key = codecs.decode(keyHex, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 2:  #Convert key from hex to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 2 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 2 hex character make 1 byte
                        key = str(input("Error! Your key should correspond to full 2-hex bytes. Please enter your key again: "))

                    key = codecs.decode(key, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 3:  #Convert key from text to unicode
                    key = str(input("Enter your key: "))
                    key = [ord(c) for c in key]


            ciphertext = RC4(key, plaintext)
            print("----------------------------------------------------")
            print("Your encoded message is:")
            print("In hex: ", ciphertext)
            print("In bin: ", hexToBin(ciphertext))
            try:
                cipher = codecs.decode(ciphertext, 'hex_codec').decode('utf-8')
                print("In text: ", cipher)
            except:
                print("Your code cannot be encoded to text. Sorry!")
            print("----------------------------------------------------")


        elif choice == 2:   #Decryption
            print("----------------------------------------------------")
            print("You chose to decrypt a message.")
            print("Is your ciphertext in: 1)binary, 2)hexadecimal or 3)regular text ?")
            cipherChoice = int(input("Enter your choice: "))
            while cipherChoice != 1 and cipherChoice != 2 and cipherChoice != 3:
                cipherChoice = int(input("Error! Please enter a valid option: "))
            print("\nWhat about your key: 1)binary, 2)hexadecimal or 3)regular text ?")
            keyChoice = int(input("Enter your choice: "))
            while keyChoice != 1 and keyChoice != 2 and keyChoice != 3:
                keyChoice = int(input("Error! Please enter a valid option: "))
            print("----------------------------------------------------")

            if cipherChoice == 1:        #Convert cipher from binary to unicode
                ciphertext = str(input("Enter your ciphertext: "))
                while len(ciphertext) % 8 != 0:  #To convert to unicode, ciphertext must be multiple of a complete byte: since 8 bits make 1 byte
                    ciphertext = str(input("Error! Your ciphertext should correspond to full bytes. Please enter your ciphertext again: "))

                #First convert binary to hex
                cipherHex = binToHex(ciphertext)
                #Then hex to unicode
                ciphertext = codecs.decode(cipherHex, 'hex_codec')

                if keyChoice == 1:    #Convert key from binary to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 8 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 8 bits make 1 byte
                        key = str(input("Error! Your key should correspond to full 8-bits bytes. Please enter your key again: "))

                    #First convert binary to hex
                    keyHex = binToHex(key)
                    #Then hex to unicode
                    key = codecs.decode(keyHex, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 2:  #Convert key from hex to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 2 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 2 hex characters make 1 byte
                        key = str(input("Error! Your key should correspond to full 2-hex bytes. Please enter your key again: "))

                    key = codecs.decode(key, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 3:  #Convert key from text to unicode
                    key = str(input("Enter your key: "))
                    key = [ord(c) for c in key]

            elif cipherChoice == 2:      #Convert cipher from hex to unicode
                ciphertext = str(input("Enter your ciphertext: "))
                while len(ciphertext) % 2 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 2 hex characters make 1 byte
                    ciphertext = str(input("Error! Your ciphertext should correspond to full 2-hex bytes. Please enter your ciphertext again: "))

                ciphertext = codecs.decode(ciphertext, 'hex_codec')

                if keyChoice == 1:    #Convert key from binary to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 8 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 8 bits make 1 byte
                        key = str(input("Error! Your key should correspond to full 8-bits bytes. Please enter your key again: "))
                    #First convert binary to hex
                    keyHex = binToHex(key)
                    #Then hex to unicode
                    key = codecs.decode(keyHex, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 2:  #Convert key from hex to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 2 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 2 hex characters make 1 byte
                        key = str(input("Error! Your key should correspond to full 2-hex bytes. Please enter your key again: "))

                    key = codecs.decode(key, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 3:  #Convert key from text to unicode
                    key = str(input("Enter your key: "))
                    key = [ord(c) for c in key]

            elif cipherChoice == 3:      #Convert cipher from text to unicode
                ciphertext = str(input("Enter your ciphertext: "))
                #First convert from text to hex
                cipherHex = textToHex(ciphertext)
                #Then from hex to unicode
                ciphertext = codecs.decode(cipherHex, 'hex_codec')

                if keyChoice == 1:    #Convert key from binary to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 8 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 8 bits make 1 byte
                        key = str(input("Error! Your key should correspond to full 8-bits bytes. Please enter your key again: "))

                    #First convert binary to hex
                    keyHex = binToHex(key)
                    #Then text to unicode
                    key = codecs.decode(keyHex, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 2:  #Convert key from hex to unicode
                    key = str(input("Enter your key: "))
                    while len(key) % 2 != 0:  #To convert to Unicode, key must be multiple of a complete byte: since 2 hex characters make 1 byte
                        key = str(input("Error! Your key should correspond to full 2-hex bytes. Please enter your key again: "))

                    key = codecs.decode(key, 'hex_codec')
                    key = [c for c in key]

                elif keyChoice == 3:  #Convert key from text to unicode
                    key = str(input("Enter your key: "))
                    key = [ord(c) for c in key]

            plaintext = RC4(key, ciphertext)
            print("----------------------------------------------------")
            print("Your encoded message is:")
            print("In hex: ", plaintext)
            print("In bin: ", hexToBin(plaintext))
            try:
                text = codecs.decode(plaintext, 'hex_codec').decode('utf-8')
                print("In text: ", text)
            except:
                print("Your code cannot be decoded to text. Sorry!")
            print("----------------------------------------------------")

        elif choice == 3:   #Exits by ending the loop
            print("----------------------------------------------------")
            print("Thanks for using our RC4 Encryptor/Decryptor. Hope to see you again soon!")
            print("----------------------------------------------------")
            loop = 0

        else:   #If any number other than 1, 2 or 3 is entered
            print ("Error! Please enter a valid option for the program.\n")

if __name__ == '__main__':
    main()

"""
Example of tests:
1-      key = Key
        plaintext = Plaintext
        ciphertext = BBF316E8D940AF0AD3

2-      key = Wiki
        plaintext = pedia
        ciphertext = 1021BF0420

3-      key = Secret
        plaintext = Attack at dawn
        ciphertext = 45A01F645FC35B383552544B9BF5
"""
