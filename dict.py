from datetime import datetime
from copy import deepcopy
from utils import *
from wep import *

words = []
def read_words(filename):
    if words == []:
        with open(filename, 'r') as f:
            aux = f.readline()
            while aux:
                words.append(aux[:-2])
                aux = f.readline()

def dictionary_attack(msg1_xor_msg2, unknown_index, m1, m2, letter_unknown_in_first_message):
    global words
    filename = "dictionary/words.txt"
    
    words_found = []
    read_words(filename)

    if letter_unknown_in_first_message == True:
        second_index = len(m2)
        for i in range(unknown_index, len(m2)):
            if m2[i] == '*':
                second_index = i
                break
    else:
        second_index = len(m1)
        for i in range(unknown_index, len(m1)):
            if m1[i] == '*':
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

def check_if_exist_uncomplete_message(possible_found_msgs):
    for m1, m2 in possible_found_msgs:
        if m1[-1] == '*' or m2[-1] == "*":
            return True
    return False

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

def keystream_reuse_attack_brute_force(c1, c2):
    found_msg1 = ''
    found_msg2 = ''
    msg1_xor_msg2 = ''

    for i in range(len(c1)):
        msg1_xor_msg2 += chr(ord(c1[i]) ^ ord(c2[i]))

    msg1_xor_msg2 = msg1_xor_msg2[:len(c1) - 4]     # eliminate crc

    possible_found_msgs = []
    possible_found_msgs.append(("*" * len(msg1_xor_msg2), "*" * len(msg1_xor_msg2)))

    while check_if_exist_uncomplete_message(possible_found_msgs):
        letter_unknown_in_first_message, m1, m2 = get_uncomplete_known_message(possible_found_msgs)

        if letter_unknown_in_first_message == True:
            unknown_index = find_unknown_index(m1)
        else:
            unknown_index = find_unknown_index(m2)

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
