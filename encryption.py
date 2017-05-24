from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os, random, sys, pkg_resources

def encrypt_file(key, filename):
	# Set the file chunk size
	chunksize = 64 * 1024

	# Create output file name & encode as bytes
	output_file_name = "ENCRYPTED_" + os.path.basename(filename)

	# Get the file size and pad number to 16 digits
	filesize = str(os.path.getsize(filename)).zfill(16).encode()

	# Initialize and generate random data for the initialization vector
	initalization_vector = Random.new().read(AES.block_size)

	# Encode the provided password/key into a bytes string
	encoded_key = key.encode()

	# Create SHA256 hash based on the provided password
	hashed_key = SHA256.new()
	hashed_key.update(encoded_key)
	
	# Initalize the encryptor with the key, mode and IV
	encryptor = AES.new(hashed_key.digest(), AES.MODE_CBC, initalization_vector)

	# Open the input file
	with open(filename, "rb") as infile:
		# Open the output file
		with open(output_file_name, "wb") as outfile:
			# Write the padded file size to the output file
			outfile.write(filesize)

			# Wrrite the IV to the output file
			outfile.write(initalization_vector)

			while True:
				# Read the data of the 'chunksize'
				chunk = infile.read(chunksize)
				
				# Break out of the loop if the chunk size is zero
				if len(chunk) == 0:
					break

				# Check if the chunk is not 16 bytes
				elif len(chunk) % 16 !=0:
					# Pad chunk to 16 bytes
					chunk += str(' ').encode() *  (16 - (len(chunk) % 16))

				# Write encrypted chunk to the output file
				outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, filename):
	# Set the filename of the decypted file
	output_file_name = "DECRYPTED_" + os.path.basename(filename[10:])

	# Set the file chunk size
	chunksize = 64 * 1024

	# Encode the provided password/key into a bytes string
	encoded_key = key.encode()

	# Create SHA256 hash based on the provided password
	hashed_key = SHA256.new()
	hashed_key.update(encoded_key)

	# Open the encrypted file in binary mode
	with open(filename, "rb") as infile:
		# Read the first 16 bytes of the file, which contains the original file size
		filesize = infile.read(16)

		# Read the next 16 bytes of the file, which contains the IV
		initalization_vector = infile.read(16)

		# Initialize the decryptor
		decryptor = AES.new(hashed_key.digest(), AES.MODE_CBC, initalization_vector)
		
		# Open the output file, which will contain the decrypted date
		with open(output_file_name, "wb") as outfile:
			while True:
				# Read a chunk based on the chunksize
				chunk = infile.read(chunksize)

				# Break if no data is read
				if len(chunk) == 0:
					break

				# Write decrypted chunk to the output file
				outfile.write(decryptor.decrypt(chunk))

			# Truncate the output file to match the original file size
			outfile.truncate(int(filesize))