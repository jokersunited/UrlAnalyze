from utils import *
import tensorflow as tf
char_dict = gen_char_dict()
embedding_layer = tf.keras.layers.Embedding(len(char_dict)+1, 128, input_length=200)

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


def get_embedding(url, length):
    embedded = embedding_layer(tf.convert_to_tensor(get_encoding(url, length)))
    return tf.expand_dims(embedded, axis=-1)


# class Url:
#     def __init__(self, url, length):
#         self.url_str = url
#         self.length = length
#
#     def get_input_shape(self):
#         return self.length, len(char_dict)
#
#     def get_encoding(self):
#         enc_list = []
#         url_str = self.url_str if len(self.url_str) <= self.length else self.url_str[:self.length]
#
#         for char in url_str:
#             if char in char_dict.keys():
#                 enc_list.append(char_dict[char])
#             else:
#                 enc_list.append(char_dict["UNK"])
#
#         for null in range(0, self.length-len(url_str)):
#             enc_list.append(0)
#
#         return enc_list
#
#     def get_embedding(self):
#         embedded = embedding_layer(tf.convert_to_tensor(self.get_encoding()))
#         return tf.expand_dims(embedded, axis=-1)

