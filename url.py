from utils import *
import tensorflow as tf

import numpy as np
char_dict = gen_char_dict()

# embedding_weights = np.asarray(np.zeros(len(char_dict)))
# one_hot = tf.one_hot(list(char_dict.values()), len(char_dict))
# embedding_weights = np.vstack((embedding_weights, one_hot))
embedding_layer = tf.keras.layers.Embedding(len(char_dict)+1, 32, input_length=200, trainable=True)

def get_encoding(url, length):
    enc_list = []
    url_str = url if len(url) <= length else url[:length]

    for char in url_str:
        if char in char_dict.keys():
            enc_list.append(char_dict[char])
        else:
            enc_list.append(char_dict["UNK"])

    for null in range(0, length - len(url_str)):
        enc_list.append(0)

    return enc_list

def strip_proto(s):
    s = s.lower().replace("www.", "")
    if "https://" in s:
        return s[8:]
    elif "http://" in s:
        return s[7:]
    else:
        return s

def get_embedding(url, length):
    embedded = embedding_layer(tf.convert_to_tensor(get_encoding(url, length)))
    return tf.expand_dims(embedded, axis=-1)
