from tensorflow import keras
from url import get_encoding
import numpy as np
import pandas as pd

def strip_proto(s):
    if "https://" in s:
        return s[8:]
    elif "http://" in s:
        return s[7:]
    else:
        return s


test_data = pd.read_csv('testing_phish.csv')
model = keras.models.load_model('model')

print(np.asarray([get_encoding(strip_proto(x), 200) for x in test_data.url]))
print(np.asarray([get_encoding(strip_proto(x), 200) for x in test_data.url]).shape)
print(np.ones(len(test_data)))
print(np.ones(len(test_data)).shape)

print(np.asarray([get_encoding(strip_proto(x), 200) for x in test_data.url]))
model.evaluate(np.asarray([get_encoding(strip_proto(x), 200) for x in test_data.url]), test_data.phish, batch_size=128)

print(test_data.url)
exit()
for url in test_data.url:
    print(strip_proto(url))
    test = model(np.asarray([get_encoding(strip_proto(url), 200)]))
    print("Testing url result (bad): " + str(test))



