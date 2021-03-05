import pickle
import json

with open ('rfmodel.pickle', 'rb') as f:
    model = pickle.load(f)
with open ('alerts.json', 'rb') as f:
    alert_ref = json.load(f)['alerts']

def get_prediction(url):
    res = model.predict(url.df)
    return res

def generate_result(url):
    result_dict = {'alerts': [], 'full': []}
    if url.get_topdomain() is True:
        result_dict['alerts'].append({'title': "This website is from a trusted domain.", 'note': ''})
    print(url.df)
    for detail, column in zip(url.df.loc[0], url.df.columns):
        print(detail, column)
        if column == 'isip' and detail == True:
            result_dict['alerts'].append(alert_ref[column])
        if column == 'proto' and detail == False:
            result_dict['alerts'].append(alert_ref[column])

    result_dict['full'] = url.generate_raw_json()
    return result_dict
