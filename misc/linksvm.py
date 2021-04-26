import pandas as pd
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn import metrics
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from sklearn.naive_bayes import MultinomialNB

from threading import Thread, Lock

from timeit import default_timer as timer
from datetime import timedelta
from RESTAPI.urlclass import LiveUrl

phish = pd.read_csv("phish2.csv")
phish_drop = phish.dropna()
print(phish_drop)

benign = pd.read_csv("benign2.csv")
benign_drop = benign.dropna()
print(benign_drop)

merge_df = phish_drop.append(benign_drop, ignore_index=True)
merge2_df = phish_drop.append(benign_drop, ignore_index=True)

feature_list = ["link", "loc", "ext", "static", "uniq"]

scaler = StandardScaler()
scaler.fit(merge2_df[feature_list])
merge2_df[feature_list] = scaler.transform(merge2_df[feature_list])

# X_df = merge_df[feature_list]

link_col = merge_df["link"].to_frame()
# print(link_col)

link_col = link_col.apply(lambda x: x / x.max(), axis=0)
merge_df['link'] = link_col['link']

X_df = merge2_df[feature_list]
X_df.reset_index(drop=True, inplace=True)

X_train, X_test, y_train, y_test = train_test_split(X_df, merge2_df['label'], test_size=0.33, random_state=42)

print(type(X_test))
# Create a svm Classifier

hyper_list = [0.0001, 0.001, 0.01, 0.1, 1, 10, 100]

result_list = []
for c in hyper_list:

    start = timer()

    # clf = svm.SVC(kernel='rbf', probability=True)  # Linear Kernel
    clf = svm.SVC(C=c, kernel="rbf", probability=True)
    # Train the model using the training sets
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    end = timer()

    # print(metrics.classification_report(y_test, y_pred, target_names=['benign', 'phish']))
    print("\nAccuracy (C: " + str(c) + ", gamma: " + str('auto') + ") - ", metrics.accuracy_score(y_test, y_pred))
    # print("\nAccuracy - ", metrics.accuracy_score(y_test, y_pred))
    print("Time taken: " + str(timedelta(seconds=end - start)))
    result_list.append([[c, 0], metrics.accuracy_score(y_test, y_pred)])


for item in result_list:
    print(str(item[0]) +" : "+ str(item[1]))

best = max(result_list, key=lambda x: x[1])[0]

clf = svm.SVC(C=best[0], kernel="rbf", probability=True)
# Train the model using the training sets
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

print(metrics.classification_report(y_test, y_pred, target_names=['benign', 'phish']))
print("\nAccuracy (C: " + str(best[0]) + ", gamma: " + str(best[1]) + ") - ", metrics.accuracy_score(y_test, y_pred))

# start = timer()
#
# rf = RandomForestClassifier(n_estimators=250)  # Linear Kernel
# rf.fit(X_train, y_train)
#
# rf_res = rf.predict(X_test)
#
# end = timer()

# exit()

# print(metrics.classification_report(y_test, rf_res, target_names=['benign', 'phish']))
# # print("\nAccuracy (C: " + str(c) + ", gamma: " + str(gamma) + ") - ", metrics.accuracy_score(y_test, y_pred))
# print("\nAccuracy - ", metrics.accuracy_score(y_test, rf_res))
# print("Time taken: " + str(timedelta(seconds=end - start)) + "\n")
#
# importances = rf.feature_importances_
#
# feature_imp = zip(feature_list, importances)
# feature_imp = sorted(feature_imp, key=lambda x: x[1], reverse=True)
#
# for feature, importance in feature_imp:
#     print('Feature: %0s, Score: %.5f' % (feature, importance))
lock = Lock()
def get_predict(url):
    url_phish = LiveUrl(url)
    # print(url_phish.get_linkperc("loc"))
    # print(url_phish.get_linkperc("ext"))
    # print(url_phish.get_linkperc("static"))
    if url_phish.dns is True and url_phish.access is True and url_phish.link_count > 0:
        data = {"link": url_phish.link_count, "loc": float(url_phish.get_linkperc("loc").split("%")[0])/100,
         "ext": float(url_phish.get_linkperc("ext").split("%")[0])/100, "static": float(url_phish.get_linkperc("static").split("%")[0])/100,
         "uniq": url_phish.get_uniqlocal()}

        url_frame = pd.DataFrame(data, index=[0])
        print(url_phish.link_dict)
        url_frame[feature_list] = scaler.transform(url_frame[feature_list])

        lock.acquire()
        print("=== URL " + url_phish.url_str + " ===")
        print(url_frame)

        # print(clf.predict_proba([data_df.iloc[0]]))
        print(clf.predict([url_frame.iloc[0]]))
        print(clf.predict_proba([url_frame.iloc[0]]))
        lock.release()
        # print(rf.predict([data_df.iloc[0]]))
    else:
        return

url_list = [
            "https://stackoverflow.com/questions/17839973/constructing-pandas-dataframe-from-values-in-variables-gives-valueerror-if-usi",
            "https://www.geeksforgeeks.org/3d-scatter-plotting-in-python-using-matplotlib/#:~:text=A%203D%20Scatter%20Plot%20is,to%20enable%20three%20dimensional%20plotting.",
            "http://xem-video-hay.tk/cgi-sys/defaultwebpage.cgi",
            "https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html",
            "https://www.google.com/search?q=hyperparameter+tuning+of+xgboost&rlz=1C1BNSD_enSG928SG928&oq=tuning+hyperparameters+of+x&aqs=chrome.1.69i57j0i22i30l2.5061j0j7&sourceid=chrome&ie=UTF-8",
            "https://mail.google.com/mail/u/0/#inbox/FMfcgxwLtZwlxFddwltzGrTfVdDqNXNz",
            "http://facebook.iframe-fb.net/",
            "https://www.linkedin.com/comm/jobs/view/2458263879?alertAction=markasviewed&savedSearchAuthToken=1%26AQHo2Tk14fxLnAAAAXjwm0wt_FtK6iOcYKaU0m3unwa-NcpnKS4SydChiRp7cpxZBJ_jotu8WjUhTbKBNMtQcfYhKa1aMZoDGhP1OWIUKDh-zcAkk1UMBSUzd4G1EWL3S1tpuWYoeByJCylRmF8Fa5_unTjBFRIk_rK-euOYH35ftXfMpVkMULWyY_JCCCu2Jfr9hnnSDAU5eXu8oJ6P-hnD-9UJSEtM4yfoqOl2n1mAtn1qxKUBKirJSRqgZDI1DkLICkn1aL-dvI_LfDQALA6KzWkg7WGd53RZ-jqjKiyUwj9cIq2Y_kmv%26AbnNLHzcLAtuGSZJZILiW2w0weCB&savedSearchId=1344799586&refId=8f24ea70-8ab4-45e2-a01e-be4ec83cd1cf&trackingId=fm1o78J67s8CKiqt81w8aA%3D%3D&midToken=AQG1OzJNmezIbA&midSig=043Ud31yg6K9I1&trk=eml-email_job_alert_digest_01-job_alert-7-member_details_mercado&trkEmail=eml-email_job_alert_digest_01-job_alert-7-member_details_mercado-null-784dwc%7Eknqdpaul%7Er3-null-jobs%7Eview&lipi=urn%3Ali%3Apage%3Aemail_email_job_alert_digest_01%3BPRPBP303RDWw7yzOOHrtBg%3D%3D",
            "https://sitsingaporetechedu-my.sharepoint.com/:w:/r/personal/1801704_sit_singaporetech_edu_sg/_layouts/15/Doc.aspx?sourcedoc=%7BB55606EE-2076-4B15-BEAA-17253FA5D4F4%7D&file=Form%20E1%20-%20Progress%20Report%20CP%20(1801704).docx&action=default&mobileredirect=true&DefaultItemOpen=1" ]

thread_list = []

for url in url_list:
    # get_predict(url)
    t = Thread(target=get_predict, args=(url,))
    t.start()
    thread_list.append(t)

for t in thread_list:
    t.join()

# print(url_frame)
# url_frame[feature_list] = scaler.transform(url_frame)
# print(url_frame)
# print(clf.predict(url_frame))
# print(clf.predict_proba(url_frame))