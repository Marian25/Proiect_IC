from wep import *
from dict import *
from binascii import crc32


def test_keystream_reuse_attack_special_case():
    IV = '000'

    msg1 = 'Message number 1'
    msg2 = 'Complete another'

    wep1 = WEP(msg1, IV)
    wep2 = WEP(msg2, IV)

    c1 = wep1.encrypt_frame()
    c2 = wep2.encrypt_frame()

    test_msg2 = keystream_reuse_attack_special_case(c1, c2, wep1.plaintext)

    if test_msg2 == wep2.plaintext:
        print('test_keystream_reuse_attack_special_case -> All good')
    else:
        print('test_keystream_reuse_attack_special_case -> Some errors here')


def test_keystream_reuse_attack():
	IV = '000'

	msg1 = 'one arm'
	msg2 = 'unicorn'

	wep1 = WEP(msg1, IV)
	wep2 = WEP(msg2, IV)

	c1 = wep1.encrypt_frame()
	c2 = wep2.encrypt_frame()

	possible_found_msgs = keystream_reuse_attack(c1, c2)

	print("Found_messages: " + str(possible_found_msgs))

	if (msg1, msg2) in possible_found_msgs or (msg2, msg1) in possible_found_msgs:
		print('test_keystream_reuse_attack -> All good')
	else:
		print('test_keystream_reuse_attack -> Some errors here')

	bool_keystream = raw_input("Do you want to find keystreams for pairs found? (y/n)\n")

	if bool_keystream == 'y':
		for i in range(len(possible_found_msgs)):
			keystream = []

			w1, w2 = possible_found_msgs[i]
			w1 = w1 + ('%08x' % (crc32(w1) & 0xffffffff)).decode('hex')
			w2 = w2 + ('%08x' % (crc32(w2) & 0xffffffff)).decode('hex')

			for j in range(len(w1)):
				keystream.append(chr(ord(w1[j]) ^ ord(c1[j])))

			keystream = ''.join(keystream)

			print("Keystream for " + str(possible_found_msgs[i]) + " is -> " + keystream.encode('hex'))

def test_keystream_reuse_attack_brute_force():
	IV = '000'

	msg1 = 'one arm'
	msg2 = 'unicorn'

	wep1 = WEP(msg1, IV)
	wep2 = WEP(msg2, IV)

	c1 = wep1.encrypt_frame()
	c2 = wep2.encrypt_frame()

	possible_found_msgs = keystream_reuse_attack_brute_force(c1, c2)
    
	print("Found_messages: " + str(possible_found_msgs))

	if (msg1, msg2) in possible_found_msgs or (msg2, msg1) in possible_found_msgs:
		print('test_keystream_reuse_attack -> All good')
	else:
		print('test_keystream_reuse_attack -> Some errors here')

	bool_keystream = raw_input("Do you want to find keystreams for pairs found? (y/n)\n")

	if bool_keystream == 'y':
		for i in range(len(possible_found_msgs)):
			keystream = []

			w1, w2 = possible_found_msgs[i]
			w1 = w1 + ('%08x' % (crc32(w1) & 0xffffffff)).decode('hex')
			w2 = w2 + ('%08x' % (crc32(w2) & 0xffffffff)).decode('hex')

			for j in range(len(w1)):
				keystream.append(chr(ord(w1[j]) ^ ord(c1[j])))

			keystream = ''.join(keystream)

			print("Keystream for " + str(possible_found_msgs[i]) + " is -> " + keystream.encode('hex'))

def test_many_pad_attack():
	IV = '000'
	messages = [' essage number u', 
				'Complete another',
				'abcdefghi klm op',
				'I was thinking u',
				'my heartais blue',
				'the sea was busy',
				'teachers are pie',
				'I am still tired',
				'the book is dam ',
				'why do you think']
    
	ciphers = []
	for message in messages:
		wep = WEP(message, IV)

		encrypted = wep.encrypt_frame()
		encrypted = encrypted.encode('hex')

		ciphers.append(encrypted)

	keystream = many_time_pad_attack(ciphers)
	keystream = keystream.decode('hex')
	
	test_message = 'I saw an unicorn'
	wep = WEP(test_message, IV)

	encrypted = wep.encrypt_frame()

	wep.update_keystream(keystream)

	decrypted = wep.decrypt_frame(encrypted)
	decrypted = decrypted[:-4]		# discard crc

	print("Plaintext before encryption 		-> " + test_message)
	print("Message decrypted with found keystream 	-> " + decrypted)

def test_message_modification_attack():
	plaintext = 'Plaintext'
	IV = '000'			# could be random

	wep = WEP(plaintext, IV)
	encrypted = wep.encrypt_frame()

	modified_cipher = message_modification_attack(encrypted)
	decrypted_modified = wep.decrypt_frame(modified_cipher)
	
	delta = 'f0'
	for i in range(1, len(encrypted) - 4):
		delta += '00'

	delta = delta.decode("hex")
	delta = delta + ('%08x' % (crc32(delta) & 0xffffffff)).decode('hex')

	initial_plaintext = ''
	for i in range(len(delta)):
		initial_plaintext += chr(ord(decrypted_modified[i]) ^ ord(delta[i]))

	initial_plaintext = initial_plaintext[:-4]		# eliminate crc

	print("Plaintext: " + plaintext)
	print("Encrypted: " + encrypted)
	print("Modified cipher: " + modified_cipher)
	print("Decrypted modified: " + decrypted_modified)
	print("Plaintext obtained: " + initial_plaintext)

	if plaintext == initial_plaintext:
		print('test_message_modification_attack -> All good')
	else:
		print('test_message_modification_attack -> Some errors here')


if __name__ == '__main__':
	print("keystream_reuse_attack_special_case runnning...")
	test_keystream_reuse_attack_special_case()
	print("keystream_reuse_attack_special_case finished\n")

	# print("keystream_reuse_attack_brute_force runnning...")
	# test_keystream_reuse_attack_brute_force()
	# print("keystream_reuse_attack_brute_force finished\n")

	print("keystream_reuse_attack runnning...")
	test_keystream_reuse_attack()
	print("keystream_reuse_attack finished\n")

	print("many_pad_attack...")
	test_many_pad_attack()
	print("many_pad_attack finished\n")

	print("message_modification_attack runnning...")
	test_message_modification_attack()
	print("message_modification_attack finished")
