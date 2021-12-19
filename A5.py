#PYTHON 3.6 IMPLEMENTATION OF A5/1
''' NOTE:
    CLOCKING BITS:
        FOR LSFR1: BIT 8
        FOR LSFR2: BIT 10
        FOR LSFR3: BIT 10
    TAPPED BITS:
        FOR LSFR1: BIT 13-16-17-18
        FOR LSFR2: BIT 20-21
        FOR LSFR3: BIT 7-20-21-22
'''    

#FUNCTIONS:
def convert_binary_to_str(binary): #converts binary to string
	s = ""
	length = len(binary) - 8
	i = 0
	while(i <= length):
		s = s + chr(int(binary[i:i+8], 2))
		i = i + 8
	return str(s)


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
    

#FUNCTION TO GET KEY:
def getKey():
    key = input("Enter the key (MAX 64-BITS): \n")
    isBinary = False
    while (isBinary == False): #makes sure the input is binary
        for i in range (len(key)):
            if (key[i] != "1" and key [i] != "0"):
                print("\n WRONG INPUT!")
                key = input("Enter the key (MAX 64-BITS): \n")
                break
            if i == len(key)-1:
                isBinary=True
    z = 64 - len (key)
    key = "0"*z+key #padding the key
    return key

#FUNCTION TO GET THE FRAME COUNTER
def getFrameCounter():
    frameCounter = input("Enter the frame counter (MAX 22-BITS):\n")
    isBinary = False
    while (isBinary == False): #makes sure the input is in binary format
        for i in range (len(frameCounter)):
            if (frameCounter[i] != "1" and frameCounter [i] != "0"):
                print("\n WRONG INPUT!")
                frameCounter = input("Enter the frame counter (MAX 22-BITS): \n")
                break
            if i == len(frameCounter)-1:
                isBinary=True
    z = 22 - len (frameCounter)
    frameCounter = z*"0" + frameCounter #padding the frameCounter
    return frameCounter

#FUNCTION TO LOAD THE REGITERS WITH THE NECESSARY XOR OPERATIONS
def loadingKeyRegisters(key):
    #initializing the shift registers with zeros
    LSFR1 = []
    LSFR2 = []
    LSFR3 = []
    for i in range (19):
        LSFR1.append(0)
        LSFR2.append(0)
        LSFR3.append(0)
    for i in range (3):
        LSFR2.append(0)
        LSFR3.append(0)
    LSFR3.append(0)

    bit1 = 0
    bit2 = 0
    bit3 = 0
    for i in range (64):
        #getting the xor values for the tapped bits
        bit1 = LSFR1[18]^LSFR1[17]^LSFR1[16]^LSFR1[13]^int(key[i])
        bit2 = LSFR2[21]^LSFR2[20]^int(key[i])
        bit3 = LSFR3[7]^LSFR3[20]^LSFR3[21]^LSFR3[22]^int(key[i])
        
        #shifting the registers (efficiently) & placing the values of the XORed tapped bits
        for j in range (22,0,-1):
            LSFR3[j] = LSFR3[j-1]
            if (j<=21):
                LSFR2[j] = LSFR2[j-1]
                if (j<=18):
                    LSFR1[j] = LSFR1[j-1]
        LSFR1[0] = bit1
        LSFR2[0] = bit2
        LSFR3[0] = bit3
    RegistersArray = [LSFR1,LSFR2, LSFR3]
    return RegistersArray

        
#FRAME COUNTER OPERATION
def frameCounterOperation (frameCounter,RegistersArray):
    LSFR1 = RegistersArray[0]
    LSFR2 = RegistersArray[1]
    LSFR3 = RegistersArray[2]
    bit1 = bit2 = bit3 = 0
    for i in range (22):
        #getting the xor values for the tapped bits
        bit1 = LSFR1[18]^LSFR1[17]^LSFR1[16]^LSFR1[13]^int(frameCounter[i])
        bit2 = LSFR2[21]^LSFR2[20]^int(frameCounter[i])
        bit3 = LSFR3[7]^LSFR3[20]^LSFR3[21]^LSFR3[22]^int(frameCounter[i])
        
        #shifting the registers (efficiently) & placing the values of the XORed tapped bits
        for j in range (22,0,-1):
            LSFR3[j] = LSFR3[j-1]
            if (j<=21):
                LSFR2[j] = LSFR2[j-1]
                if (j<=18):
                    LSFR1[j] = LSFR1[j-1]
        LSFR1[0] = bit1
        LSFR2[0] = bit2
        LSFR3[0] = bit3
    RegistersArray = [LSFR1, LSFR2, LSFR3]
    return RegistersArray

#IRREGULAR CLOCKING FOR 100 ROUNDS
def irregularClocking (RegistersArray):
    LSFR1 = RegistersArray[0]
    LSFR2 = RegistersArray[1]
    LSFR3 = RegistersArray[2]
    bit1 = bit2 = bit3 = 0
    for i in range (100):
        # majorityBit places the majority bits in an array
        majorityBit=[LSFR1[8],LSFR2[10],LSFR3[10]]
        
        #getting the xor values for the tapped bits
        bit1 = LSFR1[18]^LSFR1[17]^LSFR1[16]^LSFR1[13]
        bit2 = LSFR2[21]^LSFR2[20]
        bit3 = LSFR3[7]^LSFR3[20]^LSFR3[21]^LSFR3[22]
        
        if (sum(majorityBit)==2 or sum(majorityBit)==3): #MAJORITY BIT IS 1
        #shifting the registers (efficiently) & placing the values of the XORed tapped bits based on MB
            if LSFR1[8]==1:
                for j in range (18,0,-1):
                    LSFR1[j]=LSFR1[j-1]
                LSFR1[0]=bit1
            if LSFR2[10]==1:
                for j in range (21,0,-1):
                    LSFR2[j]=LSFR2[j-1]
                LSFR2[0]=bit2
            if LSFR3[10]==1:
                for j in range (22,0,-1):
                    LSFR3[j]=LSFR3[j-1]
                LSFR3[0]=bit3
        else: #SUM OF majorityBit is 0 or 1 => MAJORITY BIT IS 0
        #shifting the registers (efficiently) & placing the values of the XORed tapped bits based on MB
            if LSFR1[8]==0:
                for j in range (18,0,-1):
                    LSFR1[j]=LSFR1[j-1]
                LSFR1[0]=bit1
            if LSFR2[10]==0:
                for j in range (21,0,-1):
                    LSFR2[j]=LSFR2[j-1]
                LSFR2[0]=bit2
            if LSFR3[10]==0:
                for j in range (22,0,-1):
                    LSFR3[j]=LSFR3[j-1]
                LSFR3[0]=bit3
    RegistersArray = [LSFR1, LSFR2, LSFR3]
    return RegistersArray

#GENERATING THE KEYSTREAM:
def generateKeyStream(RegistersArray):
    LSFR1 = RegistersArray[0]
    LSFR2 = RegistersArray[1]
    LSFR3 = RegistersArray[2]
    bit1 = bit2 = bit3 = 0
    #initializing KeyStream
    keyStream =""
    
    for i in range (228):
        #Xoring the last bits and adding them to the keyStream
        keyStream+=str(LSFR1[18]^LSFR2[21]^LSFR3[22])
        # majorityBit places the majority bits in an array
        majorityBit=[LSFR1[8],LSFR2[10],LSFR3[10]]
        
         #getting the xor values for the tapped bits
        bit1 = LSFR1[18]^LSFR1[17]^LSFR1[16]^LSFR1[13]
        bit2 = LSFR2[21]^LSFR2[20]
        bit3 = LSFR3[7]^LSFR3[20]^LSFR3[21]^LSFR3[22]
        
        if (sum(majorityBit)==2 or sum(majorityBit)==3): #MAJORITY BIT IS 1
        #shifting the registers (efficiently) & placing the values of the XORed tapped bits based on MB

            if LSFR1[8]==1:
                for j in range (18,0,-1):
                    LSFR1[j]=LSFR1[j-1]
                LSFR1[0]=bit1
            if LSFR2[10]==1:
                for j in range (21,0,-1):
                    LSFR2[j]=LSFR2[j-1]
                LSFR2[0]=bit2
            if LSFR3[10]==1:
                for j in range (22,0,-1):
                    LSFR3[j]=LSFR3[j-1]
                LSFR3[0]=bit3
        else: #SUM OF majorityBit is 0 or 1 => MAJORITY BIT IS 0
        #shifting the registers (efficiently) & placing the values of the XORed tapped bits based on MB

            if LSFR1[8]==0:
                for j in range (18,0,-1):
                    LSFR1[j]=LSFR1[j-1]
                LSFR1[0]=bit1
            if LSFR2[10]==0:
                for j in range (21,0,-1):
                    LSFR2[j]=LSFR2[j-1]
                LSFR2[0]=bit2
            if LSFR3[10]==0:
                for j in range (22,0,-1):
                    LSFR3[j]=LSFR3[j-1]
                LSFR3[0]=bit3
    return keyStream

#GETTING THE MESSAGE/CIPHERTEXT:
def getMessage ():
    print ("\n The maximum message length is 228 bits \n")
    m = input("Enter the message that you want to encrypt:\n")
    isBinary = False
    while (isBinary == False): #makes sure the message is in binary form
        for i in range (len(m)):
            if (m[i] != "1" and m[i] != "0"):
                print("\n WRONG INPUT!")
                m = input("Enter the message you want to encrypt (MAX length = 228 bits): ")
                break
            if i == len(m)-1:
                isBinary=True
    z = 228 - len (m)
    m = z*"0" + m #padding the message
    return m

def getCiphertext ():
    print ("\n The maximum ciphertext length is 228 bits \n")
    m = input("Enter the ciphertext that you want to decrypt:\n")
    isBinary = False
    while (isBinary == False): #makes sure the ciphertext is in binary form
        for i in range (len(m)):
            if (m[i] != "1" and m[i] != "0"):
                print("\n WRONG INPUT!")
                m = input("Enter the ciphertext you want to decrypt (MAX length = 228 bits): ")
                break
            if i == len(m)-1:
                isBinary=True
    z = 228 - len (m)
    m = z*"0" + m #padding the message 
    return m

    
    
#ENCRYPTING:
def encrypt(message,key):
    #XOEing the message with the KeyStream
    ciphertext=""
    message=str(message)
    for i in range (len(message)):
        ciphertext+=str(int(key[i])^int(message[i]))
    return ciphertext

#DECRYPTING        
def decrypt(ciphertext,key):
    #XORing the ciphertext with the KeyStream
    message=""
    ciphertext=str(ciphertext)
    for i in range (len(ciphertext)):
        message+=str(int(key[i])^int(ciphertext[i]))
    return message
        
        
        
def main():
    print("----------------------------------------------------")
    print("Welcome to our A5 Encryptor/Decryptor!")
    print("----------------------------------------------------")
    loop = True
    ArrayAfterLoading=[]
    ArrayAfterFC=[]
    ArrayAfterClocking=[]
    while (loop):
        print('\n')
        print("Please choose 1 for Encryption, 2 for Decryption or 3 to Exit the program")
        choice = int(input("Enter your choice: "))
        if (1 == choice):
            print("----------------------------------------------------")
            print("You chose to encrypt a message.")
            message = getMessage()
            key=getKey()
            frameCounter = getFrameCounter()
            ArrayAfterLoading = loadingKeyRegisters(key)
            ArrayAfterFC = frameCounterOperation(frameCounter, ArrayAfterLoading)
            ArrayAfterClocking = irregularClocking(ArrayAfterFC)
            keyStream1 = generateKeyStream(ArrayAfterClocking)
            ciphertext=encrypt(message, keyStream1)
            ciphertextInHex = binToHex(ciphertext)
            print("----------------------------------------------------")
            print("Your encoded message is:")
            print ("\n")
            print("In bin: ", ciphertext)
            print ("\n")
            print("In hex: ", ciphertextInHex)
            print ("\n")
            
        elif (2 == choice):
            print("----------------------------------------------------")
            print("You chose to decrypt a message.")
            ciphertext = getCiphertext()
            key=getKey()
            frameCounter = getFrameCounter()
            ArrayAfterLoading = loadingKeyRegisters(key)
            ArrayAfterFC = frameCounterOperation(frameCounter, ArrayAfterLoading)
            ArrayAfterClocking = irregularClocking(ArrayAfterFC)
            keyStream2 = generateKeyStream(ArrayAfterClocking)
            message=decrypt(ciphertext, keyStream2)
            messageInHex = binToHex(message)
            print("----------------------------------------------------")
            print("Your decoded message is:")
            print ("\n")
            print("In bin: ", message)
            print ("\n")
            print("In hex: ", messageInHex)
            print ("\n")
        elif (3 == choice):
            print("----------------------------------------------------")
            print("Thanks for using our A5 Encryptor/Decryptor. Hope to see you again soon!")
            print("----------------------------------------------------")
            loop = False
        else:   #If any number other than 1, 2 or 3 is entered
                print ("Error! Please enter a valid option for the program.\n")

if __name__ == '__main__':
    main()
            
            
            
                
            
           
            


        
