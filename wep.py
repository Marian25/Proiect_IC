import sys
from rc4 import RC4
from binascii import crc32
from random import randint
from itertools import permutations
from copy import deepcopy
from utils import *

class WEP:

    def __init__(self, message, IV):
        self.key = 'magic'
        self.plaintext = message + ('%08x' % (crc32(message) & 0xffffffff)).decode('hex')
        self.update_keystream_from_IV(IV)

    def update_key(self, key):
        self.key = key

    def update_keystream(self, keystream):
        self.keystream = keystream

    def update_keystream_from_IV(self, IV):
        self.keystream = RC4(IV + self.key, len(self.plaintext)).keystream

    def update_plaintext(self, message):
        self.plaintext = message + ('%08x' % (crc32(message) & 0xffffffff)).decode('hex')

    def encrypt_frame(self):
        encrypted = ''
        for i in range(len(self.plaintext)):
            encrypted += chr(ord(self.plaintext[i]) ^ ord(self.keystream[i]))
        return encrypted

    def decrypt_frame(self, ciphertext):
        decrypted = ''
        for i in range(len(ciphertext)):
            decrypted += chr(ord(ciphertext[i]) ^ ord(self.keystream[i]))
        return decrypted


# keystream reuse attack (confidentiality)
# special case: if the plaintext of one of the messages is known
def keystream_reuse_attack_special_case(c1, c2, msg1):
    msg2 = ''
    for i in range(len(c1)):
        msg2 += chr((ord(c1[i]) ^ ord(c2[i]) ^ ord(msg1[i])))
    return msg2

def dictionary_attack(msg1_xor_msg2, unknown_index, m1, m2, letter_unknown_in_first_message):
	words_length = 0
	if letter_unknown_in_first_message:
		if unknown_index > 1 and m1[unknown_index] != ' ' and m1[unknown_index] != '*' and m1[unknown_index - 1] == ' ':
			words_length += 1

		for i in range(len(m1)):
			if m1[i] == '*':
				for j in range(i, len(m1)):
					if m1[j] != ' ':
						words_length += 1
					else:
						break
				break
				
	else:
		if unknown_index > 1 and m2[unknown_index] != ' ' and m2[unknown_index] != '*' and m2[unknown_index - 1] == ' ':
			words_length += 1

		for i in range(len(m2)):
			if m2[i] == '*':
				for j in range(i, len(m2)):
					if m2[j] != ' ':
						words_length += 1
					else:
						break
				break


	filename = "dictionary/words%d.txt" % words_length
    
	words_found = []
	words = []

	if words_length < 20:
		with open(filename, 'r') as f:
			aux = f.readline()
			while aux:
				ok = True
				for i in range(len(aux[:-2])):
					if letter_unknown_in_first_message:
						if m1[i + unknown_index] != '*' and m1[i + unknown_index] != aux[i]:
							ok = False
					else:
						if m2[i + unknown_index] != '*' and m2[i + unknown_index] != aux[i]:
							ok = False

				if ok:
					words.append(aux[:-2])
				aux = f.readline()
	else:
		return []

	if letter_unknown_in_first_message == True:
		second_index = len(m2)
		for i in range(unknown_index, len(m2)):
			if m2[i] == '*' or m2[i] == ' ':
				second_index = i
				break
	else:
		second_index = len(m1)
		for i in range(unknown_index, len(m1)):
			if m1[i] == '*' or m1[i] == ' ':
				second_index = i
				break

	for word in words:
		if letter_unknown_in_first_message == True:
			word_temp = m2[unknown_index:second_index]
		else:
			word_temp = m1[unknown_index:second_index]

		if word != word_temp[0:len(word_temp)-1]:
			wx = []
			for i in range(min(len(word), len(word_temp))):
				wx.append(chr(ord(word[i]) ^ ord(word_temp[i])))
			wx = ''.join(wx)

			if msg1_xor_msg2[unknown_index:unknown_index + len(wx)] == wx and word not in words_found:
				if letter_unknown_in_first_message == True and len(m1) - unknown_index >= len(word):
					words_found.append(word)
				elif letter_unknown_in_first_message == False and len(m2) - unknown_index >= len(word):
					words_found.append(word)

	return words_found

def get_uncomplete_known_message(possible_found_msgs):
    for m1, m2 in possible_found_msgs:
        for i in range(len(m1)):
            if m1[i] == '*':               # first unknown letter is in first message
                letter_unknown_in_first_message = True
                possible_found_msgs.remove((m1, m2))
                return letter_unknown_in_first_message, m1, m2
            elif m2[i] == '*':
                possible_found_msgs.remove((m1, m2))
                letter_unknown_in_first_message = False
                return letter_unknown_in_first_message, m1, m2

def find_unknown_index(message):
    for i in range(len(message)):
        if message[i] == '*':
            return i
    return None

# keystream reuse attack (confidentiality)
# both plaintexts are unknown
def keystream_reuse_attack(c1, c2):
    found_msg1 = ''
    found_msg2 = ''
    msg1_xor_msg2 = ''

    for i in range(len(c1)):
        msg1_xor_msg2 += chr(ord(c1[i]) ^ ord(c2[i]))

    msg1_xor_msg2 = msg1_xor_msg2[:len(c1) - 4]     # eliminate crc
    spaces_indexes = found_spaces(msg1_xor_msg2)

    # find chars when in same position from other word is space
    possible_found_msgs = create_possible_messages_based_on_spaces_positions(msg1_xor_msg2, spaces_indexes)
    
    # delete pairs with two consecutive spaces
    possible_found_msgs = delete_pair_with_two_consecutive_spaces(possible_found_msgs)

    # substitute positions with spaces
    possible_found_msgs = find_letters_when_corresponding_position_is_space(msg1_xor_msg2, possible_found_msgs)
    
    while check_if_exists_unknown_words(possible_found_msgs):
        letter_unknown_in_first_message, m1, m2 = get_uncomplete_known_message(possible_found_msgs)

        if letter_unknown_in_first_message == True:
            unknown_index = find_unknown_index(m1)
            if unknown_index > 2 and m1[unknown_index - 1] != ' ' and m1[unknown_index - 1] != '*' and m1[unknown_index - 2] == ' ':
				unknown_index -= 1
        else:
            unknown_index = find_unknown_index(m2)
            if unknown_index > 2 and m2[unknown_index - 1] != ' ' and m2[unknown_index - 1] != '*' and m2[unknown_index - 2] == ' ':
				unknown_index -= 1

        print(letter_unknown_in_first_message, m1, m2, unknown_index, len(possible_found_msgs))

        words_found = dictionary_attack(msg1_xor_msg2, unknown_index, m1, m2, letter_unknown_in_first_message)

        for word in words_found:
            if letter_unknown_in_first_message:
                message_copy = deepcopy(m1)
            else:
                message_copy = deepcopy(m2)

            message_copy = list(message_copy)

            for i in range(len(word)):
                message_copy[i + unknown_index] = word[i]

            if message_copy[-1] == '*':
                message_copy[len(word) + unknown_index] = ' '

            message_copy = ''.join(message_copy)

            if letter_unknown_in_first_message and (m2, message_copy) not in possible_found_msgs:
                possible_found_msgs.append((message_copy, m2))
            elif (message_copy, m1) not in possible_found_msgs:
                possible_found_msgs.append((m1, message_copy))


    return possible_found_msgs

def many_time_pad_find_keystream(ciphers, messages_length, procent_space_appearance):
    keystream = [None] * messages_length
    
    for i in range(len(ciphers)):
        counter = [0] * len(ciphers[0])

        for j in range(len(ciphers)):
            if i != j:
                ciphers_xor = sxor(ciphers[i].decode('hex'), ciphers[j].decode('hex'))
                for k in range(len(ciphers_xor)):
                    if ciphers_xor[k].isalpha():
                        counter[k] += 1
        
        space_indexes = []
        for j in range(len(counter)):
            if counter[j] >= len(ciphers) * procent_space_appearance:
                space_indexes.append(j)

        xor_with_spaces = sxor(ciphers[i].decode('hex'), ' ' * messages_length)
        for index in space_indexes:
            keystream[index] = xor_with_spaces[index].encode('hex')

    keystream_hex = ''.join([val if val is not None else '00' for val in keystream])
    
    return keystream_hex

def find_rest_chars_keystream(keystream):
    keystream = keystream.decode('hex')

    empty_position = []

    for i in range(len(keystream) - 4):
        if ord(keystream[i]) == 0:
            empty_position.append(i)

    return empty_position

def many_time_pad_attack(ciphers):
    
    messages_length = len(ciphers[0]) / 2
    procent_space_appearance = 0.7

    keystream = many_time_pad_find_keystream(ciphers, messages_length, procent_space_appearance)
    empty_position = find_rest_chars_keystream(keystream)

    print("unable to find char in keystream at positions: " + str(empty_position))

    return keystream

# data integrity
# message modification
def message_modification_attack(cipher):

    delta = 'f0'
    for i in range(1, len(cipher) - 4):
        delta += '00'

    delta = delta.decode("hex")
    delta = delta + ('%08x' % (crc32(delta) & 0xffffffff)).decode('hex')

    modified_cipher = ''
    for i in range(len(delta)):
        modified_cipher += chr(ord(cipher[i]) ^ ord(delta[i]))

    return modified_cipher 


if __name__ == '__main__':
    pass
    