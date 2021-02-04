from tensorflow import keras
from url import get_encoding
import numpy as np
import pandas as pd

def strip_proto(s):
    if "https://" in s:
        return s[8:]
    else:
        return s[7:]

test_data = pd.read_csv('misc/phish.csv')
model = keras.models.load_model('misc/model/model')

print(np.asarray([get_encoding(strip_proto(x), 200) for x in test_data.url]))
print(np.asarray([get_encoding(strip_proto(x), 200) for x in test_data.url]).shape)
print(np.ones(len(test_data)))
print(np.ones(len(test_data)).shape)


model.evaluate(np.asarray([get_encoding(x, 200) for x in test_data.url]), np.ones(len(test_data)))

print(test_data.url)
for url in test_data.url:
    test = model(np.asarray([get_encoding(strip_proto(url), 200)]))
    print("Testing url result (bad): " + str(test))



