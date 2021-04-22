import pandas as pd
from sklearn import svm
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn import metrics
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from timeit import default_timer as timer
from datetime import timedelta

phish = pd.read_csv("phish2.csv")
phish_drop = phish.dropna()
print(phish_drop)

benign = pd.read_csv("benign2.csv")
benign_drop = benign.dropna()
print(benign_drop)

merge_df = phish_drop.append(benign_drop, ignore_index=True)
merge2_df = phish_drop.append(benign_drop, ignore_index=True)


feature_list = ["link","loc", "ext", "static", "uniq"]

scaler = StandardScaler()
scaler.fit(merge2_df[feature_list])
merge2_df[feature_list] = scaler.transform(merge2_df[feature_list])

# X_df = merge_df[feature_list]

link_col = merge_df["link"].to_frame()
# print(link_col)

link_col = link_col.apply(lambda x: x/x.max(), axis=0)
merge_df['link'] = link_col['link']

X_df = merge2_df[feature_list]

X_train, X_test, y_train, y_test = train_test_split(X_df, merge2_df['label'], test_size=0.3)
#Create a svm Classifier

hyper_list = [0.0001, 0.001, 0.01, 0.1, 1, 10, 100]


result_list = []
for c in hyper_list:
    start = timer()

    clf = svm.SVC(kernel='rbf', C=c, probability=True) # Linear Kernel

    #Train the model using the training sets
    clf.fit(X_train, y_train)

    y_pred=clf.predict(X_test)

    end = timer()


    # print(metrics.classification_report(y_test, y_pred, target_names=['benign', 'phish']))
    print("\nAccuracy (C: " + str(c) + ", gamma: " + str("auto") + ") - ", metrics.accuracy_score(y_test, y_pred))
    # print("\nAccuracy - ", metrics.accuracy_score(y_test, y_pred))
    print("Time taken: " + str(timedelta(seconds=end - start)))
    result_list.append(metrics.accuracy_score(y_test, y_pred))

start = timer()

rf = RandomForestClassifier(n_estimators=1000) # Linear Kernel
rf.fit(X_train, y_train)

rf_res=rf.predict(X_test)

end = timer()


# print(metrics.classification_report(y_test, y_pred, target_names=['benign', 'phish']))
# print("\nAccuracy (C: " + str(c) + ", gamma: " + str(gamma) + ") - ", metrics.accuracy_score(y_test, y_pred))
print("\nAccuracy - ", metrics.accuracy_score(y_test, rf_res))
print("Time taken: " + str(timedelta(seconds=end - start)))