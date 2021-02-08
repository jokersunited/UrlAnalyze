import tensorflow as tf
import pandas as pd
from url import get_encoding, char_dict, embedding_layer, get_embedding
from modeltester import strip_proto
import numpy as np
from sklearn.model_selection import train_test_split

from tensorflow.keras import Sequential
from tensorflow.keras.layers import Conv1D, Dense, MaxPool1D, LSTM, ReLU, Softmax, Dropout, Flatten, Input, Concatenate, UpSampling1D, ZeroPadding1D, Reshape
from tensorflow.keras.models import Model
from tensorflow.keras.callbacks import Callback

from time import time
import matplotlib.pyplot as plt

def strip_proto(s):
    if "https://" in s:
        return s[8:]
    else:
        return s[7:]

def get_encoding_proto(url, length):
    url = strip_proto(url)
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

class TimeHistory(Callback):
    def on_train_begin(self, logs={}):
        self.times = []

    def on_epoch_begin(self, batch, logs={}):
        self.epoch_time_start = time()

    def on_epoch_end(self, batch, logs={}):
        self.times.append(time() - self.epoch_time_start)


url_df = pd.read_csv('urldata.csv')
test_df = pd.read_csv('testing_phish.csv')

url_df = url_df.sample(frac=1).reset_index(drop=True)

url_df = url_df.truncate(after=10000)
url_df.loc[url_df.label == 'good', 'label'] = 0
url_df.loc[url_df.label == 'bad', 'label'] = 1

X_train, X_test, y_train, y_test = train_test_split(url_df.url, url_df.result, test_size=0.33)
batch_size = 64

# good_df = url_df[url_df.label == 0].to_numpy()
# bad_df = url_df[url_df.label == 1].to_numpy()

# url_df = url_df.to_numpy()

# print(good_df)
# print(bad_df)

# url = Url(url_df.loc[url_df.index[93], 'url'], 200)
# url_ts = url.get_embedding()
# exit()
#
# print(url_ts)
print(X_train)
print(get_embedding("radiofreecharlotte.uncc.edu/", 200))
# exit()

X_train = np.asarray([get_encoding(strip_proto(url), 200) for url in X_train])
X_test = np.asarray([get_encoding_proto(strip_proto(url), 200) for url in test_df.url])
y_test = np.asarray(test_df.phish).astype('float32')

print(X_train)
print(np.asarray(y_train))


def convulations(input_shape=(200, 32)):
    inp = Input(shape=input_shape)
    convs = []
    for k_no in range(3, 7):
        conv = Conv1D(256, kernel_size=k_no,  activation='relu', input_shape=input_shape)(inp)
        conv = MaxPool1D()(conv)
        conv = Reshape(target_shape=(-1,))(conv)
        convs.append(conv)

    out = Concatenate()(convs)

    return Model(inputs=inp, outputs=out)

def create_model(url_len, filters=32, kernel_size=3, lstm_units=16, dropout=0.2):

    pool = int(kernel_size/2)

    model = Sequential()
    model.add(embedding_layer)
    model.add(Conv1D(filters=64, kernel_size=3))
    model.add(ReLU())
    model.add(MaxPool1D(pool_size=2))
    # model.add(Dense(256))
    # model.add(Dropout(0.3))
    # model.add(Dense(128))
    model.add(LSTM(units=70, return_sequences=True))
    # model.add(Dropout(dropout))
    model.add(Softmax())
    model.add(Flatten())
    model.add(Dense(1, activation='sigmoid'))

    inputs = Input(shape=(url_len, ))
    outputs = model(inputs)

    model.summary()

    return Model(inputs=inputs, outputs=outputs)

def get_results(name, filters=32, kernel_size=4, lstm_units=16, dropout=0.2):

    model = create_model(200, filters=filters, kernel_size=kernel_size, lstm_units=lstm_units, dropout=dropout)
    opt = tf.keras.optimizers.Adam(learning_rate=0.1)
    model.compile(optimizer=opt, loss=tf.keras.losses.BinaryCrossentropy(), metrics=['accuracy'])

    time_callback = TimeHistory()
    history = model.fit(X_train, np.asarray(y_train).astype('float32'), epochs=20, batch_size=batch_size, validation_data=(X_test, y_test), validation_steps=24, callbacks=[time_callback])

    test = model(np.asarray([get_encoding("adserving.favorit-network.com/eas?camp=19320;cre=mu&grpid=1738&tag_id=618&nums=FGApbjFAAA", 200)]))
    print("Testing url result (bad): " + str(test))

    test = model(np.asarray([get_encoding("stormpages.com/script/ping.txt", 200)]))
    print("Testing url result (bad): " + str(test))

    test = model(np.asarray([get_encoding("santacruzsuspension.com/?j=bleach-episode-245", 200)]))
    print("Testing url result (bad): " + str(test))

    test = model(np.asarray([get_encoding("ratevin.com/story.php?title=jean-simmons-died-british-actress-jean-simmons-dead-jean-simmons-dies-in-los-angeles", 200)]))
    print("Testing url result (good): " + str(test))

    test = model(np.asarray([get_encoding("fanbase.com/Arkansas-Razorbacks-Mens-Basketball-1985-86", 200)]))
    print("Testing url result (good): " + str(test))

    test = model(np.asarray([get_encoding("mmaroot.com/david-loiseau-vs-charles-mccarthy-fight-video/", 200)]))
    print("Testing url result (good): " + str(test))

    test = model(np.asarray([get_encoding("thestar.com/news/canada/politics/article/1067979--three-criminal-charges-for-tony-tomassi-ex-member-of-charest-cabinet-in-quebec", 200)]))
    print("Testing url result (good): " + str(test))

    accuracy = model.evaluate(X_test, y_test, batch_size=128)
    model.save('model')
    return [history, name, time_callback.times, accuracy]


# result1 = get_results('16F-4K-16L', filters=16, lstm_units=16)
# result2 = get_results('32F-4K-32L', filters=32, lstm_units=32)
# result3 = get_results('64F-4K-64L', filters=64, lstm_units=64)
# result1 = get_results('16F-4K-16L', filters=16, lstm_units=16)
# result2 = get_results('32F-4K-32L', filters=32, lstm_units=16)
# result3 = get_results('64F-4K-64L', filters=64, lstm_units=16)
# result4 = get_results('16F-2K-16L', filters=16, lstm_units=16, kernel_size=2)
# result5 = get_results('32F-2K-32L', filters=32, lstm_units=32, kernel_size=2)
# result6 = get_results('64F-2K-64L', filters=64, lstm_units=64, kernel_size=2)
result7 = get_results('256F-4K-32L', filters=256, lstm_units=64)
# result8 = get_results('64F-4K-32L', filters=64, lstm_units=32)
# result9 = get_results('64F-4K-64L', filters=64, lstm_units=64)

# model_list = [result1,result2,result3,result4,result5,result6,result7,result8,result9]
model_list = [result7]


# print(result1[0].history.keys())
#  "Accuracy"
# f1=plt.figure(1)
# for result in model_list:
#     plt.plot(result[0].history['accuracy'])
# plt.title('model accuracy')
# plt.ylabel('accuracy')
# plt.xlabel('epoch')
# plt.legend([result[1] for result in model_list], loc='upper left')
# # "Time"
# f2=plt.figure(2)
# for result in model_list:
#     plt.plot(result[2])
# plt.title('model cost')
# plt.ylabel('training time (/s)')
# plt.xlabel('epoch')
# plt.legend([result[1] for result in model_list], loc='upper left')
#
# f3=plt.figure(3)
# for result in model_list:
#     plt.plot(result[0].history['loss'])
# plt.title('model loss')
# plt.ylabel('loss')
# plt.xlabel('epoch')
# plt.legend([result[1] for result in model_list], loc='upper left')
#
# plt.show()

# for i in range(0, 1000):
#     # Take a random sample of the good batch to train
#     idx = np.random.randint(0, len(good_df), batch_size)
#     good_batch = np.array(good_df)[idx]
#     good_batch = np.array([Url(x, 200).get_embedding() for x in good_batch])
#
#     idx = np.random.randint(0, len(bad_df), batch_size)
#     bad_batch = np.array(bad_df)[idx]
#     bad_batch = np.array([Url(x, 200).get_embedding() for x in bad_batch])
#
#     loss_real = model.train_on_batch(good_batch, np.zeros((batch_size, 1)))
#     loss_fake = model.train_on_batch(bad_batch, np.ones((batch_size, 1)))
#
#     print("\n%d Iterations [Real loss: %f, Fake loss: %f]" % (i, loss_real, loss_fake))
