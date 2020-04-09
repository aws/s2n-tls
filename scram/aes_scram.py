# SCRAM mode Python script
from Crypto.Cipher import AES
from Crypto import Random
rndfile = Random.new()
import hashlib
import hmac
import sys
 
DEBUG_ENABLED = True

# When reading/writing byte strings, the first (aka left-most) byte is the Most Significant Byte (aka Big-Endian) 
# (Eg "0x0001", 0x00 is the MSB and 0x01 is the LSB, meaning 0x0001 == 1)
ENDIANNESS = 'big'

# Convert Integer value to byte string
def byteStr(val, numBytes):
	return val.to_bytes(numBytes, ENDIANNESS)

# Debug Print Byte String to Standard Out
def debugByteStr(debugStr, byteStrVal):
	if DEBUG_ENABLED:
		print(debugStr + ": 0x" +  byteStrVal.hex().upper())

# Debug Print Integer value to Standard Out
def debugInt(debugStr, intVal):
	if DEBUG_ENABLED:
		print(debugStr + ": " +  str(intVal))

# Generate a random Key
def scram_generate_key():
	# Generate Random 32 Byte Key
	K = rndfile.read(32)
	debugByteStr("K", K)
	
	return K

def scram_encrypt(K, N, A, M, F):
	"""
	SCRAM Encryption
	
	Parameters:
		K: Key
		N: Nonce
		A: Additional Authenticated Data
		M: Plaintext Message
		F: Frame Size
		
	Returns:
		C: Ciphertext
		X: Excrypted R and Padding Len
		Tag: Authentication Tag
	"""
	# Generate a random 32-byte value R
	R = rndfile.read(32)
	
	# Prepare the Padding. We append 0x00 bytes to the end up to the next frame size.
	M_LEN = len(M)
	PADDING_LEN = 0
	
	if (F > 0):
		PADDING_LEN = (F - M_LEN) % F
	
	PADDING_STR = byteStr(0x0, PADDING_LEN)
	PADDING_LEN_STR = byteStr(PADDING_LEN, 2)
	PADDED_MSG = M + PADDING_STR

	debugInt("len(M)", M_LEN)
	debugInt("PADDING_LEN", PADDING_LEN)
	debugByteStr("PADDING_STR", PADDING_STR)
	debugByteStr("PADDING_LEN_STR", PADDING_LEN_STR)
	debugByteStr("PADDED_MSG", PADDED_MSG)
	
	# Derive Message encryption key (KE)
	# S1 = N || 0x00 0x00 0x00 0x1 || 0^{8} || 0^{8} || 0^{16} || R 
	S1 = N + byteStr(0x01, 4) + byteStr(0x0, 8) +  byteStr(0x0, 8) + byteStr(0x0, 16) + R
	U1 = hmac.new(K, S1, hashlib.sha512).digest()
	KE = U1[0:32]
	
	# AES_CTR encrypt PADDED_MSG with Nonce N and Key KE
	C = AES.new(key=KE, mode=AES.MODE_CTR, nonce=N).encrypt(PADDED_MSG)
	 
	# Derive MAC Key (KM) used to with GMAC to generate T
	# S2 = N || 0x00 0x00 0x00 0x2 || 0^{8} || 0^{8} || 0^{16} || 0^{32}
	S2 = N +  byteStr(0x02, 4) + byteStr(0x0, 8) +  byteStr(0x0, 8) + byteStr(0x0, 16) + byteStr(0x0, 32)
	U2 = hmac.new(K, S2, hashlib.sha512).digest()
	KM = U2[0:32]
	 
	# GMAC the string A || C , using the GMAC key KM and nonce N
	T = AES.new(key=KM, mode=AES.MODE_GCM, nonce=N).update(A + C).digest()
	 
	# Derive a one-time pad (U3) from T
	# S3 = N || 0x00 0x00 0x00 0x3 || 0^{8} || 0^{8} || T || 0^{32}
	S3 = N + byteStr(0x03, 4) + byteStr(0x0, 8) +  byteStr(0x0, 8) + T + byteStr(0x0, 32)
	U3 = hmac.new(K, S3, hashlib.sha512).digest()
	
	# Encrypt R and PaddingLen with one-time pad U3
	Y1 = bytes(a ^ b for (a,b) in zip (U3[0:32], R))
	Y0 = bytes(a ^ b for (a,b) in zip (U3[32:34], PADDING_LEN_STR))
	X = Y1 + Y0
	
	# Authenticate (Tag) T and R
	# S4 = N || 0x00 0x00 0x00 0x4 || A_LEN_STR || M_LEN_STR || T || R 
	S4 = N + byteStr(0x04, 4) + byteStr(len(A), 8) + byteStr(M_LEN, 8) + T + R
	U4 = hmac.new(K, S4, hashlib.sha512).digest()  
	
	# Truncate to 16 bytes tag
	Tag = U4[0:16] 
	
	debugByteStr("S1", S1)
	debugByteStr("S2", S2)
	debugByteStr("S3", S3)
	debugByteStr("S4", S4)
	debugByteStr("U1", U1)
	debugByteStr("U2", U2)
	debugByteStr("U3", U3)
	debugByteStr("U4", U4)
	debugByteStr("Y0", Y0)
	debugByteStr("Y1", Y1)
	debugByteStr("T", T)
	debugByteStr("KE", KE)
	debugByteStr("KM", KM)
	debugInt("len(C)", len(C))
	debugByteStr("C", C)
	debugByteStr("X", X)
	debugByteStr("Tag", Tag)
	
	return C, X, Tag


def scram_decrypt(K, N, A, C, X, Tag):
	"""
	SCRAM Decryption
	
	Parameters:
		K: Key
		N: Nonce
		A: Additional Authenticated Data
		C: Ciphertext
		X: Encrypted Random value R and Padding Length
		Tag: Tag
		
	Returns:
		M_calculated: The decrypted Message
	"""
	
	# Derive MAC key (KM)
	# S2 = N || 0x00 0x00 0x00 0x2 || 0^{8} || 0^{8} || 0^{16} || 0^{32}
	S2_calculated = N + byteStr(0x02, 4) + byteStr(0x0, 8) +  byteStr(0x0, 8) + byteStr(0x0, 16) + byteStr(0x0, 32)
	U2_calculated = hmac.new(K, S2_calculated, hashlib.sha512).digest()
	KM_calculated = U2_calculated[0:32]

	# Derive T
	# T = GMAC (N, A||C, null)
	T_calculated  = AES.new(key=KM_calculated, mode=AES.MODE_GCM, nonce=N).update(A + C).digest()
	  
	# Derive one-time pad U3 from T_calculated, 
	# S3 = N || 0x00 0x00 0x00 0x3 || 0^{8} || 0^{8} || T || 0^{32}
	S3_calculated  = N + byteStr(0x03, 4) + byteStr(0x0, 8) +  byteStr(0x0, 8) + T_calculated + byteStr(0x0, 32)
	U3_calculated  = hmac.new(K, S3_calculated, hashlib.sha512).digest()
	
	# Decrypt R and PADDING_LEN, by xor'ing X and U3 
	R_calculated = bytes(a ^ b for (a,b) in zip (U3_calculated[0:32], X[0:32]))
	PADDING_LEN_STR_calculated = bytes(a ^ b for (a,b) in zip (U3_calculated[32:34], X[32:34]))
	
	# Derive Message and Padding Lengths
	PADDING_LEN_calculated = int.from_bytes(PADDING_LEN_STR_calculated, ENDIANNESS)
	M_LEN_calculated = len(C) - PADDING_LEN_calculated
	
	# Authenticate R
	# S4 = N || 0x00 0x00 0x00 0x4 || A_LEN_STR || M_LEN_STR || T || R 
	S4_calculated  = N + byteStr(0x04, 4) + byteStr(len(A), 8) + byteStr(M_LEN_calculated, 8) + T_calculated + R_calculated
	U4_calculated  = hmac.new(K, S4_calculated, hashlib.sha512).digest()
	Tag_calculated = U4_calculated[0:16]
	 
	if(Tag == Tag_calculated):
	    print ("PASSED: Authentication")
	else:
	    print ("FAILED: Authentication")
	    return None
	 
	# Now that Ciphertext and other parameters are authenticated, we can decrypt Ciphertext to get Plaintext
	# Derive Message Encryption key (KE)
	# S1 = N || 0x00 0x00 0x00 0x1 || 0^{8} || 0^{8} || 0^{16} || R 
	S1_calculated = N + byteStr(0x01, 4) + byteStr(0x0, 8) +  byteStr(0x0, 8) + byteStr(0x0, 16) + R_calculated
	U1_calculated = hmac.new(K, S1_calculated, hashlib.sha512).digest()
	KE_calculated = U1_calculated[0:32]
	
	# Decrypt Ciphertext
	PADDED_MSG_calculated  = AES.new(key=KE_calculated, mode=AES.MODE_CTR, nonce=N).decrypt(C)
	
	# Strip off padding bytes
	M_calculated = PADDED_MSG_calculated[0:M_LEN_calculated]
	
	if DEBUG_ENABLED:
		print("\nDecryption Debug Info: ")
		debugByteStr("S1_calculated", S1_calculated)
		debugByteStr("S2_calculated", S2_calculated)
		debugByteStr("S3_calculated", S3_calculated)
		debugByteStr("S4_calculated", S4_calculated)
		debugByteStr("U1_calculated", U1_calculated)
		debugByteStr("U2_calculated", U2_calculated)
		debugByteStr("U3_calculated", U3_calculated)
		debugByteStr("U4_calculated", U4_calculated)
		debugByteStr("T_calculated", T_calculated)
		debugByteStr("R_calculated", R_calculated)
		debugByteStr("KE_calculated", KE_calculated)
		debugByteStr("KM_calculated", KM_calculated)
		debugByteStr("PADDED_MSG_calculated", PADDED_MSG_calculated)
		debugByteStr("M_calculated", M_calculated)
		
	return M_calculated


def main(argv):
	# Generate Random 28 Byte Message
	M = rndfile.read(28)
	debugByteStr("M", M)
	
	# Generate Random 28 Byte Additional Authenticated Data
	A = rndfile.read(28)
	debugByteStr("A", A)
	
	# Generate Random 12 Byte Key 
	N = rndfile.read(12)
	
	# Frame Size. Messages will be padded up to the next Frame size before being encrypted.
	F = 32
	debugInt("F", F)

	K = scram_generate_key()
	
	C, X, Tag = scram_encrypt(K, N, A, M, F)
	
	M_calculated = scram_decrypt(K, N, A, C, X, Tag)
	
	if(M != M_calculated):
		print ("FAILED: Decryption")
	else:
		print("PASSED: Decryption")
	
	return

if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
