'''
cobaltstrike任务解密
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


def readInt(buf):
	return struct.unpack('>L', buf[0:4])[0]

#接收到的任务数据
shell_whoami="0k6lSpOcdzWFzgaXLVIG3KScxMndHJzDRt//TUIqQSgtJdnQHkbXaatrNiizJJrj+9e4q7iHpPnaxEFMfRFluw=="

if __name__ == "__main__":
	#key源自Beacon_metadata_RSA_Decrypt.py
	SHARED_KEY = binascii.unhexlify("")
	HMAC_KEY = binascii.unhexlify("")

	enc_data = base64.b64decode(shell_whoami)
	print("数据总长度:{}".format(len(enc_data)))
	signature = enc_data[-16:]
	encrypted_data = enc_data[:-16]

	iv_bytes = bytes("abcdefghijklmnop",'utf-8')

	dec = decrypt(encrypted_data,iv_bytes,signature,SHARED_KEY,HMAC_KEY)

	counter = readInt(dec)
	print("时间戳:{}".format(counter))

	decrypted_length = readInt(dec[4:])
	print("任务数据包长度:{}".format(decrypted_length))

	data = dec[8:len(dec)]
	print("任务Data")
	print(hexdump.hexdump(data))

	# 任务标志
	Task_Sign=data[0:4]
	print("Task_Sign:{}".format(Task_Sign))

	# 实际的任务数据长度
	Task_file_len = int.from_bytes(data[4:8], byteorder='big', signed=False)
	print("Task_file:{}".format(Task_file_len))

	with open('data.bin', 'wb') as f:
		f.write(data[8:Task_file_len])

	print(hexdump.hexdump(data[Task_file_len:]))
