import tensorflow as tf
import keras
import pickle
import json
#
# from urlclass import Url

physical_devices = tf.config.list_physical_devices('GPU')
try:
    tf.config.experimental.set_memory_growth(physical_devices[0], True)
except:
  # Invalid device or cannot modify virtual devices once initialized.
    pass

# Load and initialise the RandomForest model
with open('./data/rfmodel.pickle', 'rb') as f:
    model = pickle.load(f)

# Load and initialize the json alert object
with open ('alerts.json', 'rb') as f:
    alert_ref = json.load(f)['alerts']

# Load and initialize the CNN model
model_char = keras.models.load_model('./data/modelchar')

# Generate a dictionary with character mapping
def gen_char_dict():
    """
    Generates a character dictionary with integer mapping
    :return: Dictionary of characters mapped to an integer
    """
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-;.!?:'\"/\|_@#$%^&*~`+-=<>()[]{}"
    char_dict = {}
    char_dict["null"] = 0
    for i, char in enumerate(alphabet):
        char_dict[char] = i + 1
    char_dict["UNK"] = len(alphabet) + 1
    return char_dict

# Create variable to store the created character mapping dictionary
char_dict = gen_char_dict()

def strip_proto(s):
    """
    Removes protocol text from URLs
    :param s: String to remove protocol
    :return: String with protocol removed
    """
    return s.replace("https://", "").replace("http://", "").replace("www.", "")

def get_encoding_proto(url, length):
    """
    Maps the URL to its respective character encoding integer
    :param url: String representation of the URL
    :param length: Max length of the URL
    :return: List of integers representing the characters of the URL
    """
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

def get_rfprediction(url):
    """
    Gets prediction from the random forest classifier
    :param url: Url object
    :return: 1 for phishing 0 for benign
    """
    res = model.predict(url.generate_df())
    return int(res[0])

def get_cnnprediction(url):
    """
    Gets prediction from the CNN Model
    :param url: Url object
    :return: Float percentage probability of phishing
    """
    char_X = tf.constant([get_encoding_proto(url.url_str, 200)])
    return float(model_char(char_X)[0][1])*100

def get_result(url):
    pass
def generate_result(url):
    result_dict = {'alerts': [], 'full': []}
    result_dict['result'] = True
    if url.get_topdomain() is True:
        result_dict['alerts'].append(alert_ref['topdomain'])
        result_dict['result'] = False
    url_df = url.generate_df()
    result_dict['rf'] = "Phishing" if get_rfprediction(url) == 1 else "Benign"
    result_dict['cnn'] = "Phishing" if get_cnnprediction(url) > 50 else "Benign"

    for detail, column in zip(url_df.loc[0], url_df.columns):
        print(detail, column)
        if column == 'isip' and detail == True:
            result_dict['alerts'].append(alert_ref[column])
        if column == 'proto' and detail == False:
            result_dict['alerts'].append(alert_ref[column])
        if column == 'atchar' and detail == True:
            result_dict['alerts'].append(alert_ref[column])
        if column == 'domlen' and detail >= 20:
            result_dict['alerts'].append(alert_ref[column])

    result_dict['full'] = url.generate_raw_json()
    return result_dict