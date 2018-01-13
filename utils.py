

def char_to_bin(s):
    return list("{:08b}".format(ord(s)))

def sxor(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

def strbin(s):
    return ''.join("{:08b}".format(ord(x)) for x in s)

# found spaces in plaintexts xor (if starts with 010)
def found_spaces(msg1_xor_msg2):
    indexes = []

    for i in range(len(msg1_xor_msg2)):
        bits = char_to_bin(msg1_xor_msg2[i])

        if bits[0] == '0' and bits[1] == '1' and bits[2] == '0':
            indexes.append(i)

    return indexes

def get_next_space_index(s, space_index):
    index = space_index + 1

    while index < len(s) and s[index] != ' ':
        index += 1

    return index

def get_previous_space_index(s, space_index):
    index = space_index

    while index > 0 and s[index] != ' ':
        index -= 1

    return index

def get_beggining_word_index(s1, s2):
    for i in range(len(s1)):
        if s1[i] == '*' or s2[i] == '*':
            return True, i

        if s2[i] == '*':
            return False, i

def check_if_exists_unknown_words(possible_found_msgs):
    for w1, w2 in possible_found_msgs:
        if w1[-1] == '*' or w2[-1] == '*':
            return True

    return False

def get_unknown_words(possible_found_msgs):
    for w1, w2 in possible_found_msgs:
        if '*' in w1 or '*' in w2:
            possible_found_msgs.remove((w1, w2))
            return w1, w2

def substitute_word(word, substitution, start_index):
    word_list = list(word)
    substitution_list = list(substitution)

    for i in range(len(substitution_list)):
        word_list[start_index + i] = substitution_list[i]

    return ''.join(word_list)


def create_possible_messages_based_on_spaces_positions(msg1_xor_msg2, spaces_indexes):
    possible_found_msgs = []

    for i in range(2**len(spaces_indexes)):
        found_msg1 = list('*' * len(msg1_xor_msg2))
        found_msg2 = list('*' * len(msg1_xor_msg2))
        
        l = list("{:08b}".format(i))
        for i in range(len(spaces_indexes)):
            if l[7 - i] == '1':
                found_msg1[spaces_indexes[i]] = ' '

        for i in range(len(spaces_indexes)):
            if l[7 - i] == '0':
                found_msg2[spaces_indexes[i]] = ' '        

        possible_found_msgs.append((''.join(found_msg1), ''.join(found_msg2)))

    return possible_found_msgs

def delete_pair_with_two_consecutive_spaces(possible_found_msgs):

    for w1, w2 in possible_found_msgs[:]:
        for i in range(len(w1) - 1):
            if w1[i] == ' ' and w1[i+1] == ' ':
                possible_found_msgs.remove((w1, w2))
                break

        for i in range(len(w2) - 1):
            if w2[i] == ' ' and w2[i+1] == ' ':
                possible_found_msgs.remove((w1, w2))
                break

    return possible_found_msgs

def find_letters_when_corresponding_position_is_space(msg1_xor_msg2, possible_found_msgs):
    for w1, w2 in possible_found_msgs[:]:
        possible_found_msgs.remove((w1, w2))
        list_word1 = list(w1)
        list_word2 = list(w2)

        for i in range(len(list_word1)):
            if list_word1[i] == ' ':
                list_word2[i] = chr(ord(msg1_xor_msg2[i]) ^ ord(' '))

        for i in range(len(list_word2)):
            if list_word2[i] == ' ':
                list_word1[i] = chr(ord(msg1_xor_msg2[i]) ^ ord(' '))

        possible_found_msgs.append((''.join(list_word1), ''.join(list_word2)))

    return possible_found_msgs
