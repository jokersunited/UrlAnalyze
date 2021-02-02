def gen_char_dict():
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-;.!?:'\"/\|_@#$%^&*~`+-=<>()[]{}"
    char_dict = {}
    char_dict["null"] = 0
    for i, char in enumerate(alphabet):
        char_dict[char] = i + 1
    char_dict["UNK"] = len(alphabet)+1
    return char_dict
