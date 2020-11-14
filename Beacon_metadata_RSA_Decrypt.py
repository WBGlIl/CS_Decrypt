'''
Beacon元数据
'''
import hashlib
import M2Crypto
import base64
import hexdump

PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
{}
-----END RSA PRIVATE KEY-----
"""

encode_data = ""
base64_key = ""

pubkey = M2Crypto.RSA.load_key_string(PRIVATE_KEY.format(base64_key).encode())
ciphertext = pubkey.private_decrypt(base64.b64decode(encode_data), M2Crypto.RSA.pkcs1_padding)


def isFlag(var, flag):
	return (var & flag) == flag


def toIP(var):
	var2 = (var & -16777216) >> 24
	var4 = (var & 16711680) >> 16
	var6 = (var & 65280) >> 8
	var8 = var & 255
	return str(var2) + "." + str(var4) + "." + str(var6) + "." + str(var8)


def getName(var0):
	if var0 == 37:
		return "IBM037"
	elif var0 == 437:
		return "IBM437"
	elif var0 == 500:
		return "IBM500"
	elif var0 == 708:
		return "ISO-8859-6"
	elif var0 == 709:
		return ""
	elif var0 == 710:
		return ""
	elif var0 == 720:
		return "IBM437"
	elif var0 == 737:
		return "x-IBM737"
	elif var0 == 775:
		return "IBM775"
	elif var0 == 850:
		return "IBM850"
	elif var0 == 852:
		return "IBM852"
	elif var0 == 855:
		return "IBM855"
	elif var0 == 857:
		return "IBM857"
	elif var0 == 858:
		return "IBM00858"
	elif var0 == 860:
		return "IBM860"
	elif var0 == 861:
		return "IBM861"
	elif var0 == 862:
		return "IBM862"
	elif var0 == 863:
		return "IBM863"
	elif var0 == 864:
		return "IBM864"
	elif var0 == 865:
		return "IBM865"
	elif var0 == 866:
		return "IBM866"
	elif var0 == 869:
		return "IBM869"
	elif var0 == 870:
		return "IBM870"
	elif var0 == 874:
		return "x-windows-874"
	elif var0 == 875:
		return "IBM875"
	elif var0 == 932:
		return "Shift_JIS"
	elif var0 == 936:
		return "x-mswin-936"
	elif var0 == 949:
		return "x-windows-949"
	elif var0 == 950:
		return "Big5"
	elif var0 == 1026:
		return "IBM1026"
	elif var0 == 1047:
		return "IBM1047"
	elif var0 == 1140:
		return "IBM01140"
	elif var0 == 1141:
		return "IBM01141"
	elif var0 == 1142:
		return "IBM01142"
	elif var0 == 1143:
		return "IBM01143"
	elif var0 == 1144:
		return "IBM01144"
	elif var0 == 1145:
		return "IBM01145"
	elif var0 == 1146:
		return "IBM01146"
	elif var0 == 1147:
		return "IBM01147"
	elif var0 == 1148:
		return "IBM01148"
	elif var0 == 1149:
		return "IBM01149"
	elif var0 == 1200:
		return "UTF-16LE"
	elif var0 == 1201:
		return "UTF-16BE"
	elif var0 == 1250:
		return "windows-1250"
	elif var0 == 1251:
		return "windows-1251"
	elif var0 == 1252:
		return "windows-1252"
	elif var0 == 1253:
		return "windows-1253"
	elif var0 == 1254:
		return "windows-1254"
	elif var0 == 1255:
		return "windows-1255"
	elif var0 == 1256:
		return "windows-1256"
	elif var0 == 1257:
		return "windows-1257"
	elif var0 == 1258:
		return "windows-1258"
	elif var0 == 1361:
		return "x-Johab"
	elif var0 == 10000:
		return "x-MacRoman"
	elif var0 == 10001:
		return ""
	elif var0 == 10002:
		return ""
	elif var0 == 10003:
		return ""
	elif var0 == 10004:
		return "x-MacArabic"
	elif var0 == 10005:
		return "x-MacHebrew"
	elif var0 == 10006:
		return "x-MacGreek"
	elif var0 == 10007:
		return "x-MacCyrillic"
	elif var0 == 10008:
		return ""
	elif var0 == 10010:
		return "x-MacRomania"
	elif var0 == 10017:
		return "x-MacUkraine"
	elif var0 == 10021:
		return "x-MacThai"
	elif var0 == 10029:
		return "x-MacCentralEurope"
	elif var0 == 10079:
		return "x-MacIceland"
	elif var0 == 10081:
		return "x-MacTurkish"
	elif var0 == 10082:
		return "x-MacCroatian"
	elif var0 == 12000:
		return "UTF-32LE"
	elif var0 == 12001:
		return "UTF-32BE"
	elif var0 == 20000:
		return "x-ISO-2022-CN-CNS"
	elif var0 == 20001:
		return ""
	elif var0 == 20002:
		return ""
	elif var0 == 20003:
		return ""
	elif var0 == 20004:
		return ""
	elif var0 == 20005:
		return ""
	elif var0 == 20105:
		return ""
	elif var0 == 20106:
		return ""
	elif var0 == 20107:
		return ""
	elif var0 == 20108:
		return ""
	elif var0 == 20127:
		return "US-ASCII"
	elif var0 == 20261:
		return ""
	elif var0 == 20269:
		return ""
	elif var0 == 20273:
		return "IBM273"
	elif var0 == 20277:
		return "IBM277"
	elif var0 == 20278:
		return "IBM278"
	elif var0 == 20280:
		return "IBM280"
	elif var0 == 20284:
		return "IBM284"
	elif var0 == 20285:
		return "IBM285"
	elif var0 == 20290:
		return "IBM290"
	elif var0 == 20297:
		return "IBM297"
	elif var0 == 20420:
		return "IBM420"
	elif var0 == 20423:
		return ""
	elif var0 == 20424:
		return "IBM424"
	elif var0 == 20833:
		return ""
	elif var0 == 20838:
		return "IBM-Thai"
	elif var0 == 20866:
		return "KOI8-R"
	elif var0 == 20871:
		return "IBM871"
	elif var0 == 20880:
		return ""
	elif var0 == 20905:
		return ""
	elif var0 == 20924:
		return ""
	elif var0 == 20932:
		return "EUC-JP"
	elif var0 == 20936:
		return "GB2312"
	elif var0 == 20949:
		return ""
	elif var0 == 21025:
		return "x-IBM1025"
	elif var0 == 21027:
		return ""
	elif var0 == 21866:
		return "KOI8-U"
	elif var0 == 28591:
		return "ISO-8859-1"
	elif var0 == 28592:
		return "ISO-8859-2"
	elif var0 == 28593:
		return "ISO-8859-3"
	elif var0 == 28594:
		return "ISO-8859-4"
	elif var0 == 28595:
		return "ISO-8859-5"
	elif var0 == 28596:
		return "ISO-8859-6"
	elif var0 == 28597:
		return "ISO-8859-7"
	elif var0 == 28598:
		return "ISO-8859-8"
	elif var0 == 28599:
		return "ISO-8859-9"
	elif var0 == 28603:
		return "ISO-8859-13"
	elif var0 == 28605:
		return "ISO-8859-15"
	elif var0 == 29001:
		return ""
	elif var0 == 38598:
		return "ISO-8859-8"
	elif var0 == 50220:
		return "ISO-2022-JP"
	elif var0 == 50221:
		return "ISO-2022-JP-2"
	elif var0 == 50222:
		return "ISO-2022-JP"
	elif var0 == 50225:
		return "ISO-2022-KR"
	elif var0 == 50227:
		return "ISO-2022-CN"
	elif var0 == 50229:
		return "ISO-2022-CN"
	elif var0 == 50930:
		return "x-IBM930"
	elif var0 == 50931:
		return ""
	elif var0 == 50933:
		return "x-IBM933"
	elif var0 == 50935:
		return "x-IBM935"
	elif var0 == 50936:
		return ""
	elif var0 == 50937:
		return "x-IBM937"
	elif var0 == 50939:
		return "x-IBM939"
	elif var0 == 51932:
		return "EUC-JP"
	elif var0 == 51936:
		return "GB2312"
	elif var0 == 51949:
		return "EUC-KR"
	elif var0 == 51950:
		return ""
	elif var0 == 52936:
		return "GB2312"
	elif var0 == 54936:
		return "GB18030"
	elif var0 == 57002:
		return "x-ISCII91"
	elif var0 == 57003:
		return "x-ISCII91"
	elif var0 == 57004:
		return "x-ISCII91"
	elif var0 == 57005:
		return "x-ISCII91"
	elif var0 == 57006:
		return "x-ISCII91"
	elif var0 == 57007:
		return "x-ISCII91"
	elif var0 == 57008:
		return "x-ISCII91"
	elif var0 == 57009:
		return "x-ISCII91"
	elif var0 == 57010:
		return "x-ISCII91"
	elif var0 == 57011:
		return "x-ISCII91"
	elif var0 == 65000:
		return ""
	elif var0 == 65001:
		return "UTF-8"


if ciphertext[0:4] == b'\x00\x00\xBE\xEF':

	# 16
	raw_aes_keys = ciphertext[8:24]

	# 2
	var9 = ciphertext[24:26]
	var9 = int.from_bytes(var9, byteorder='little', signed=False)
	var9 = getName(var9)
	# 2
	var10 = ciphertext[26:28]
	var10 = int.from_bytes(var10, byteorder='little', signed=False)
	var10 = getName(var10)

	# 4
	id = ciphertext[28:32]
	id = int.from_bytes(id, byteorder='big', signed=False)
	print("Beacon id:{}".format(id))

	# 4
	pid = ciphertext[32:36]
	pid = int.from_bytes(pid, byteorder='big', signed=False)
	print("pid:{}".format(pid))

	# 2
	port = ciphertext[36:38]
	port = int.from_bytes(port, byteorder='big', signed=False)
	print("port:{}".format(port))

	# 1
	flag = ciphertext[38:39]
	flag = int.from_bytes(flag, byteorder='big', signed=False)
	# print(flag)

	if isFlag(flag, 1):
		barch = ""
		pid = ""
		is64 = ""
	elif isFlag(flag, 2):
		barch = "x64"
	else:
		barch = "x86"

	if isFlag(flag, 4):
		is64 = "1"
	else:
		is64 = "0"

	if isFlag(flag, 8):
		bypassuac = "True"
	else:
		bypassuac = "False"

	print("barch:" + barch)
	print("is64:" + is64)
	print("bypass:" + bypassuac)

	# 2
	var_1 = ciphertext[39:40]
	var_2 = ciphertext[40:41]
	var_1 = int.from_bytes(var_1, byteorder='big', signed=False)
	var_2 = int.from_bytes(var_2, byteorder='big', signed=False)
	windows_var = str(var_1) + "." + str(var_2)
	print("windows var:" + windows_var)

	# 2
	windows_build = ciphertext[41:43]
	windows_build = int.from_bytes(windows_build, byteorder='big', signed=False)
	print("windows build:{}".format(windows_build))

	# 4
	x64_P = ciphertext[43:47]

	# 4
	ptr_gmh = ciphertext[47:51]
	# 4
	ptr_gpa = ciphertext[51:55]

	# if ("x64".equals(this.barch)) {
	# this.ptr_gmh = CommonUtils.join(var10, this.ptr_gmh)
	# this.ptr_gpa = CommonUtils.join(var10, this.ptr_gpa)
	# }
	#
	# this.ptr_gmh = CommonUtils.bswap(this.ptr_gmh)
	# this.ptr_gpa = CommonUtils.bswap(this.ptr_gpa)

	# 4
	intz = ciphertext[55:59]
	intz = int.from_bytes(intz, byteorder='little', signed=False)
	intz = toIP(intz)

	if intz == "0.0.0.0":
		intz = "unknown"
	print("host:" + intz)

	if var9 == None:
		ddata = ciphertext[59:len(ciphertext)].decode("ISO8859-1")
	else:
		# ??x-mswin-936
		# ddata = ciphertext[59:len(ciphertext)].decode(var9)
		ddata = ciphertext[59:len(ciphertext)].decode("ISO8859-1")

	ddata = ddata.split("\t")
	if len(ddata) > 0:
		computer = ddata[0]
	if len(ddata) > 1:
		username = ddata[1]
	if len(ddata) > 2:
		process = ddata[2]

	print("PC name:" + computer)
	print("username:" + username)
	print("process name:" + process)

	raw_aes_hash256 = hashlib.sha256(raw_aes_keys)
	digest = raw_aes_hash256.digest()
	aes_key = digest[0:16]
	hmac_key = digest[16:]

	print("AES key:{}".format(aes_key.hex()))
	print("HMAC key:{}".format(hmac_key.hex()))



	print(hexdump.hexdump(ciphertext))
