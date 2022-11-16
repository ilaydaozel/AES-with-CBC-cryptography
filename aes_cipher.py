#260201037
#python aes_cipher.py enc -m "A secret message" -p "My password" -k 32 -f enc_info.json

import sys
import json
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import padding
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def PKCS7(mes_byte):
    """#mes_byte = "971ACD01C9C7ADEACC83257926F490FF"
    mes_mod_16 = len(mes_byte)%16  #length of the message is divided in 2 because it is in hexadecimal notation and 2 hex becomes one byte
    print("mod", mes_mod_16)
    mes_remaining = int(16- mes_mod_16)
    if(mes_remaining == 0):
        mes_remaining = 16
    print("remaining: ", mes_remaining)
    
    hex_values = [b'01', b'02', "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", "10"]
    padded_mes = mes_byte + (hex_values[mes_remaining-1]*mes_remaining)
    padded_mes = mes_byte + chr(mes_remaining)*mes_remaining
    print("padded message", padded_mes)"""
    padder = padding.PKCS7(128).padder()  #128bits = 16 bytes
    padded_data = padder.update(mes_byte)
    padded_data += padder.finalize()

    return padded_data
        


def encrypt():
    if (sys.argv[1]=="enc"):
        print("encryption")
        if(len(sys.argv)==10):
            if(sys.argv[2] == "-m"):
                message = sys.argv[3] 
            if(sys.argv[4] == "-p"):
                password = sys.argv[5].encode() #encoding password for the scrypt algorithm
            if(sys.argv[6] == "-k"):
                key_len = sys.argv[7]   
            if(sys.argv[8] == "-f"):
                file_name = sys.argv[9]                  
        else:
            raise Exception("There are missing values.")   
                
    """       
    salt = get_random_bytes(128) #salt should be 128 bits long as it is mentioned in the homework
    key = scrypt(password, salt, key_len, N=2**14, r=16, p=1) 
    """
    
    mes_encoded = message.encode()
    password = b'my super secret'
    salt = get_random_bytes(16)
    key = scrypt(password, salt, int(key_len), N=2**14, r=16, p=1)
    padded_mes = PKCS7(mes_encoded) 
    
    #AES WITH CBC

    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(padded_mes, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv':iv, 'ciphertext':ct})
    with open(file_name, 'w') as f:
        f.write(result)
        data = json.load(f)
        print(data)
        

    print("Encryption result: ", result)
    #'{"iv": "bWRHdzkzVDFJbWNBY0EwSmQ1UXFuQT09", "ciphertext": "VDdxQVo3TFFCbXIzcGpYa1lJbFFZQT09"}'

        

def decrypt():
    print("Decryption")



def main():
    if (sys.argv[1]=="enc"):
        encrypt()
    
    elif(sys.argv[1]=="dec"):    
        decrypt()
    else:    
        print("Invalid")

main()        