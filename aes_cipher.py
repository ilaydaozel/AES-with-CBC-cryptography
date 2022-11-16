#260201037
#for encryption:
#python aes_cipher.py enc -m "A secret message" -p "My password" -k 32 -f enc_info.json
#for decryption:
#python aes_cipher.py dec -p "My password" -k 32 -f enc_info.json
    
import sys
import json
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

def pad_PKCS7(mes_byte):
    padder = padding.PKCS7(128).padder()  #128bits = 16 bytes
    padded_data = padder.update(mes_byte)
    padded_data += padder.finalize()

    return padded_data


def unpad_PKCS7(mes_byte):        
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(mes_byte)
    unpadded_data = data + unpadder.finalize()
    return unpadded_data

def encrypt():

    if(len(sys.argv)==10):
        if(sys.argv[2] == "-m"):
            message = sys.argv[3] 
        if(sys.argv[4] == "-p"):
            password = sys.argv[5]
        if(sys.argv[6] == "-k"):
            key_len = sys.argv[7]   
        if(sys.argv[8] == "-f"):
            file_name = sys.argv[9]                  
    else:
        raise Exception("There are missing values.")   
    
    mes_encoded = message.encode()
    print("pass before", password)
    password = password.encode() #encoding password for the scrypt algorithm
    salt = get_random_bytes(16) #salt should be 16bytes (128 bits) long as it is mentioned in the homework
    print("enc salt: ", salt)
    key = scrypt(password, salt, int(key_len), N=2**14, r=16, p=1)
    print("key enc:", key)    
    padded_mes = PKCS7(mes_encoded) 
    
    #AES WITH CBC
    
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(padded_mes, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    salt = b64encode(salt).decode('utf-8') #to be able to print 
    
    with open(file_name, 'w+') as f:
        f.write(json.dumps({'salt': salt, 'iv':iv, 'ciphertext':ct}))
    
    print("Encryption result: ")
    with open(file_name, 'r') as f:   
        result = json.load(f)
        print(result)    
    

        

def decrypt():
    if(len(sys.argv)==8):
        if(sys.argv[2] == "-p"):
            password = sys.argv[3].encode() #encoding password for the scrypt algorithm
        if(sys.argv[4] == "-k"):
            key_len = sys.argv[5]   
        if(sys.argv[6] == "-f"):
            file_name = sys.argv[7]                  
    else:
        raise Exception("There are missing values.")  
    

    """  
    with open(file_name, 'r') as f:   
        enc_file = json.load(f)
    
    enc_values = list(enc_file.values())
    salt = enc_values[0]
    iv = enc_values[1]
    ciphertext = enc_values[2]
    
    password = password.decode('utf-8')
    salt = b64encode(salt).decode('utf-8') #salt should be 16bytes (128 bits) long as it is mentioned in the homework
    """
    
    
    """with open(file_name, 'r') as f: 
        b64 = json.loads(f) 
    salt = b64decode(b64['salt'])
    key = scrypt(password, salt, int(key_len), N=2**14, r=16, p=1)
    """

    
    #  try:
    with open(file_name, 'r') as f: 
        b64 = json.loads(f.read()) 
    print("b64", b64)    
    #b64 = json.loads(file_name) 
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    salt = b64decode(b64['salt'])
    print( "dec salt: ", salt)
    key = scrypt(password, salt, int(key_len), N=2**14, r=16, p=1)
    print("key dec:", key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    print("The message was: ", unpad_PKCS7(pt))
    """    
    except (ValueError) as e:
        print("Incorrect value ", e)
    except (KeyError) as e:
        print("Incorrect key ", e)
    """


def main():
    if (sys.argv[1]=="enc"):
        encrypt()
    
    elif(sys.argv[1]=="dec"):    
        decrypt()
    else:    
        print("Invalid")

main()        


