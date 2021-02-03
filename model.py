import tensorflow as tf
import pandas as pd
from url import get_embedding, char_dict
import numpy as np

from tensorflow.keras import Sequential
from tensorflow.keras.layers import Convolution1D, Dense, MaxPool1D, LSTM, ReLU, Flatten
from tensorflow.keras.models import Model
from tensorflow.keras.callbacks import Callback

from time import time
import matplotlib.pyplot as plt

class TimeHistory(Callback):
    def on_train_begin(self, logs={}):
        self.times = []

    def on_epoch_begin(self, batch, logs={}):
        self.epoch_time_start = time()

    def on_epoch_end(self, batch, logs={}):
        self.times.append(time() - self.epoch_time_start)

url_df = pd.read_csv('data.csv')
test_df = pd.read_csv('urldata.csv')

test_df = test_df.sample(frac=1).reset_index(drop=True)
test_df = test_df.truncate(after=10000)

url_df = url_df.sample(frac=1).reset_index(drop=True)
url_df = url_df.truncate(after=35000)
url_df.loc[url_df['label'] == 'good', 'label'] = 0
url_df.loc[url_df['label'] == 'bad', 'label'] = 1
batch_size = 64

# good_df = url_df[url_df.label == 0].to_numpy()
# bad_df = url_df[url_df.label == 1].to_numpy()

url_df = url_df.to_numpy()
test_df = test_df.to_numpy()

# print(good_df)
# print(bad_df)

# url = Url(url_df.loc[url_df.index[93], 'url'], 200)
# url_ts = url.get_embedding()
# exit()
#
# print(url_ts)

test_data = [get_embedding(url, 200) for url in test_df[:, 1]]
data = [get_embedding(url, 200) for url in url_df[:, 0]]


def create_model(url_len, filters=32, kernel_size=4, lstm_units=16, dropout=0.2):

    pool = int(kernel_size/2)

    model = Sequential()
    model.add(Convolution1D(filters=filters, kernel_size=kernel_size))
    model.add(ReLU())
    model.add(MaxPool1D(pool_size=pool))
    model.add(LSTM(units=lstm_units, dropout=dropout, return_sequences=True))
    model.add(Flatten())
    model.add(Dense(1, activation='sigmoid'))

    inputs = tf.keras.layers.Input(shape=(url_len, 64))
    outputs = model(inputs)

    model.summary()

    return Model(inputs=inputs, outputs=outputs)

def get_results(name, filters=32, kernel_size=4, lstm_units=16, dropout=0.2):

    model = create_model(200, filters=filters, kernel_size=kernel_size, lstm_units=lstm_units, dropout=dropout)
    opt = tf.keras.optimizers.Adam(learning_rate=0.01)
    model.compile(optimizer=opt, loss=tf.keras.losses.BinaryCrossentropy(), metrics=['accuracy'])

    time_callback = TimeHistory()
    history = model.fit(np.asarray(data), np.asarray(url_df[:, 1]).astype('float32'), epochs=20, batch_size=64, callbacks=[time_callback])

    test = model(np.asarray([get_embedding("adserving.favorit-network.com/eas?camp=19320;cre=mu&grpid=1738&tag_id=618&nums=FGApbjFAAA", 200)]))
    print("Testing url result (bad): " + str(test))

    test = model(np.asarray([get_embedding("stormpages.com/script/ping.txt", 200)]))
    print("Testing url result (bad): " + str(test))

    test = model(np.asarray([get_embedding("santacruzsuspension.com/?j=bleach-episode-245", 200)]))
    print("Testing url result (bad): " + str(test))

    test = model(np.asarray([get_embedding("ratevin.com/story.php?title=jean-simmons-died-british-actress-jean-simmons-dead-jean-simmons-dies-in-los-angeles", 200)]))
    print("Testing url result (good): " + str(test))

    test = model(np.asarray([get_embedding("fanbase.com/Arkansas-Razorbacks-Mens-Basketball-1985-86", 200)]))
    print("Testing url result (good): " + str(test))

    test = model(np.asarray([get_embedding("mmaroot.com/david-loiseau-vs-charles-mccarthy-fight-video/", 200)]))
    print("Testing url result (good): " + str(test))

    test = model(np.asarray([get_embedding("thestar.com/news/canada/politics/article/1067979--three-criminal-charges-for-tony-tomassi-ex-member-of-charest-cabinet-in-quebec", 200)]))
    print("Testing url result (good): " + str(test))

    accuracy = model.evaluate(np.asarray(test_data), np.asarray(test_df[:, 3]).astype('float32'))
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
result7 = get_results('64F-4K-16L', filters=64, lstm_units=32)
# result8 = get_results('64F-4K-32L', filters=64, lstm_units=32)
# result9 = get_results('64F-4K-64L', filters=64, lstm_units=64)

# model_list = [result1,result2,result3,result4,result5,result6,result7,result8,result9]
model_list = [result7]


# print(result1[0].history.keys())
#  "Accuracy"
f1=plt.figure(1)
for result in model_list:
    plt.plot(result[0].history['accuracy'])
plt.title('model accuracy')
plt.ylabel('accuracy')
plt.xlabel('epoch')
plt.legend([result[1] for result in model_list], loc='upper left')
# "Time"
f2=plt.figure(2)
for result in model_list:
    plt.plot(result[2])
plt.title('model cost')
plt.ylabel('training time (/s)')
plt.xlabel('epoch')
plt.legend([result[1] for result in model_list], loc='upper left')

f3=plt.figure(3)
for result in model_list:
    plt.plot(result[0].history['loss'])
plt.title('model loss')
plt.ylabel('loss')
plt.xlabel('epoch')
plt.legend([result[1] for result in model_list], loc='upper left')

plt.show()

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
