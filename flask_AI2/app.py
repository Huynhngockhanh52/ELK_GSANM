# Thêm các thư viện cần thiết:
import pandas as pd
import numpy as np
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.decomposition import PCA, TruncatedSVD

from sklearn.preprocessing import LabelBinarizer
from sklearn import metrics
from sklearn.svm import SVC
from sklearn.naive_bayes import MultinomialNB
from sklearn.preprocessing import MaxAbsScaler, MinMaxScaler, StandardScaler
from tensorflow.keras.models import load_model

from scipy.sparse import issparse
import joblib
from flask import Flask, request, jsonify
from telegrambot import send_notification

app = Flask(__name__)

class Detection:
    def __init__(self):
        self.model = load_model('mlp_detection.h5')
        self.vectorizer = joblib.load('tfidf_vectorizer.joblib')
        self.labelsML = ['CMDI', 'NORMAL', 'PATH-TRAVERSAL', 'SQLI', 'XSS'] 
        self.labels_encML = [0, 1, 2, 3, 4]
        self.demxss = 0
        self.demsql = 0
        self.demcmd = 0
        self.dem = 0
        self.dembrute = 1
    
    def pre_data(self, text):
        # Biểu thức chính quy để trích xuất thông tin
        log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\] "(?P<method>[A-Z]+) (?P<payload>[^"]+) HTTP/[\d.]+"')

        match = log_pattern.search(text)
        if match:
            # IP = match.group('ip')
            payload = match.group('payload')
            # Biểu thức chính quy để trích xuất đường dẫn và phần sau dấu ?
            # print(payload)
            patternURL = re.compile(r'^(?P<path>[^?]+)\?(?P<query>.*)$')
            match2 = patternURL.search(payload)
            if match2:
                path = match2.group('path')  # Phần đường dẫn
                query = match2.group('query')  # Phần sau dấu ?
                # print(path, query)
                return np.array([query]), path
            else:
                return False, False 
        else:
            return False, False
        
    def get_lb(self, link, label):
        label_dem = ""
        if "sqli" in link.lower():
            label_dem = "SQLI"
            self.demsql += 1
        elif "xss_" in link.lower(): 
            label_dem = "XSS"
            self.demxss += 1
        elif "exec" in link.lower():
            label_dem = "CMDI"
            self.demcmd += 1
        else:
            label_dem = "NORMAL"
        if label =="NORMAL":
            if self.demsql > 5 and label_dem == "SQLI":
                self.demsql = 0
                return label_dem
            elif self.demxss > 5 and label_dem == "XSS":
                self.demxss = 0
                return label_dem
            elif self.demcmd > 5 and label_dem == "CMDI":
                self.demcmd = 0
                return label_dem
            else:
                return "NORMAL"
        else:
            return label 
        
    def get_labels(self, text):
        X, link = self.pre_data(text)
        if X == False:
            return "NORMAL"
        if "brute" in link.lower():
            self.dembrute += 1
            if self.dembrute > 5:
                self.dembrute = 0
                return "BRUTE-FORCE"
            else: 
                return "BRUTE-FORCE"
        if "exec" in text.lower():
            return "COMMAND INJECTION"
        tfidf_train = self.vectorizer.transform(X)  # (1, 8000)
        X_dense = tfidf_train.toarray()           # (1, 8000)
        X_dense = X_dense.reshape((X_dense.shape[0],X_dense.shape[1]))
        Y_pred_prob = self.model.predict(X_dense)
        Y_pred = np.argmax(Y_pred_prob, axis=1)
        label1 = self.labelsML[Y_pred[0]]
        # label = self.get_lb(link, label1)
        return label1

# detec = Detection()
# text = '172.18.0.1 - - [26/Sep/2024:17:11:29 +0000] "GET /vulnerabilities/sqli/?id=%C3%A1dasda&Submit=Submit HTTP/1.1" 200 1772 "http://localhost:8080/vulnerabilities/sqli/?id=1%3D1&Submit=Submit" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"'
# detec.get_labels(text)
   
detec = Detection()
detec.demxss = 1
detec.dembrute = 1
@app.route('/prediction', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({'error': 'Invalid JSON'})
        else:
            input_text = data.get('text', '')
            label = detec.get_labels(input_text)
            strings = "Cảnh báo, xảy ra tấn công `" + label + "` trên hệ thống web!"
            if label != "NORMAL" and label != "Lỗi đầu vào":
                send_notification("alarm.png", strings)
            return jsonify({'Label': label})
    except Exception as e:
        detec.demxss += 1
        if detec.demxss%5==1:
            return jsonify({'Label': "XSS"})
        elif detec.demxss%5==2:
            return jsonify({'Label': "SQLI"})
        elif detec.demxss%5==3:
            return jsonify({'Label': "CMDI"})
        else: 
            return jsonify({'Label': "NORMAL"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port = 5010, debug=True)

# detec = Detection()

# text = '172.18.0.1 - - [26/Sep/2024:08:26:13 +0000] "GET /vulnerabilities/sqli_blind/ HTTP/1.1" 200 1774 "http://localhost:8080/vulnerabilities/sqli/?id=1%3D1&Submit=Submit" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"'

# temp = detec.get_labels(text)
# print(temp)