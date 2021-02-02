import tensorflow as tf
import pandas as pd
from url import Url
import numpy as np

from tensorflow.keras import Sequential
from tensorflow.keras.layers import Convolution2D, Softmax, Dense, MaxPool2D, Flatten, LSTM, Reshape
from tensorflow.keras.models import Model

url_df = pd.read_csv('misc/phish.csv')
batch_size = 20

# url = Url(url_df.loc[url_df.index[93], 'url'], 200)
# url_ts = url.get_embedding()

# print(url_ts)

def create_model(url_len):

    model = Sequential()
    model.add(Convolution2D(32, 2, 2, activation='relu', input_shape=(url_len, 64, 1)))
    model.add(MaxPool2D(pool_size=(2, 2)))
    model.add(Reshape([int(url_len/4), -1]))
    model.add(LSTM(50, return_sequences=True))
    model.add(Flatten())
    model.add(Dense(1, activation='softmax'))

    inputs = tf.keras.layers.Input(shape=(url_len, 64, 1))
    outputs = model(inputs)

    model.summary()

    return Model(inputs=inputs, outputs=outputs)


model = create_model(200)
model.compile(optimizer='sgd', loss=tf.keras.losses.BinaryCrossentropy())

for i in range(0, 100):
    # Take a random sample of the good batch to train
    idx = np.random.randint(0, len(url_df), batch_size)
    good_list_t = np.array(url_df)[idx]
    good_list_t = np.array([Url(x, 200).get_embedding() for x in good_list_t])
    # print(good_list_t)
    # print(tf.shape(good_list_t))
    loss_real = model.train_on_batch(good_list_t, np.ones((batch_size, 1)))
    print("Loss: " + str(loss_real*100))
