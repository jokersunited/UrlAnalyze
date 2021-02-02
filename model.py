import tensorflow as tf
import pandas as pd
from url import Url
import numpy as np

from tensorflow.keras import Sequential
from tensorflow.keras.layers import Convolution2D, Dense, MaxPool2D, Flatten, LSTM, Reshape
from tensorflow.keras.models import Model

url_df = pd.read_csv('data.csv')
url_df = url_df.sample(frac=1).reset_index(drop=True)
url_df = url_df.truncate(after=1500)
url_df.loc[url_df['label'] == 'good', 'label'] = 0
url_df.loc[url_df['label'] == 'bad', 'label'] = 1
batch_size = 64

good_df = url_df[url_df.label == 0].to_numpy()
bad_df = url_df[url_df.label == 1].to_numpy()

url_df = url_df.to_numpy()

# print(good_df)
# print(bad_df)

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


data = [Url(url, 200).get_embedding() for url in url_df[:, 0]]
# print(data)
# print(url_df[:, 1])
# print(np.asarray(url_df[:, 1]).astype('float32'))

model = create_model(200)
model.compile(optimizer='sgd', loss=tf.keras.losses.BinaryCrossentropy(), metrics=['accuracy'])
model.fit(np.asarray(data), np.asarray(url_df[:, 1]).astype('float32'), epochs=150, batch_size=64)
accuracy = model.evaluate(data, np.asarray(url_df[:, 1]).astype('float32'))
print('Accuracy: %.2f' % (accuracy*100))


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
