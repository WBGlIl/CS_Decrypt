'''
Beacon任务执行结果解密
'''
import hmac
import binascii
import base64
import struct
import hexdump
from Crypto.Cipher import AES

def compare_mac(mac, mac_verif):
	if mac == mac_verif:
		return True
	if len(mac) != len(mac_verif):
		print
		"invalid MAC size"
		return False

	result = 0

	for x, y in zip(mac, mac_verif):
		result |= x ^ y

	return result == 0

def decrypt(encrypted_data, iv_bytes, signature, shared_key, hmac_key):
	if not compare_mac(hmac.new(hmac_key, encrypted_data, digestmod="sha256").digest()[0:16], signature):
		print("message authentication failed")
		return

	cypher = AES.new(shared_key, AES.MODE_CBC, iv_bytes)
	data = cypher.decrypt(encrypted_data)
	return data

#key源自Beacon_metadata_RSA_Decrypt.py
SHARED_KEY = binascii.unhexlify("")
HMAC_KEY = binascii.unhexlify("")

encrypt_data="AAAAQPmxmlOwWb3bsWCXfcZJL5HJqg3HfMKEVuoGvTGOGB1Imr8hvN3n01GWoneTc3pm0tLFrWZC7QGoGvp7JfZOa1o="

encrypt_data=base64.b64decode(encrypt_data)

encrypt_data_length=encrypt_data[0:4]

encrypt_data_length=int.from_bytes(encrypt_data_length, byteorder='big', signed=False)

encrypt_data_l = encrypt_data[4:len(encrypt_data)]

data1=encrypt_data_l[0:encrypt_data_length-16]
signature=encrypt_data_l[encrypt_data_length-16:encrypt_data_length]
iv_bytes = bytes("abcdefghijklmnop",'utf-8')

dec=decrypt(data1,iv_bytes,signature,SHARED_KEY,HMAC_KEY)


counter = dec[0:4]
counter=int.from_bytes(counter, byteorder='big', signed=False)
print("counter:{}".format(counter))

dec_length = dec[4:8]
dec_length=int.from_bytes(dec_length, byteorder='big', signed=False)
print("任务返回长度:{}".format(dec_length))

de_data= dec[8:len(dec)]
Task_type=de_data[0:4]
Task_type=int.from_bytes(Task_type, byteorder='big', signed=False)
print("任务输出类型:{}".format(Task_type))

print(de_data[4:dec_length].decode('utf-8'))

print(hexdump.hexdump(dec))