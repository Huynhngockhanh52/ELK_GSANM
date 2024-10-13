# Thêm các thư viện cần thiết:
import numpy as np 
import pandas as pd 
import re
from pre_url import PreURL
import joblib
from flask import Flask, request, jsonify
from telegrambot import send_notification


app = Flask(__name__)

class Detection:
    def __init__(self):
        self.model = joblib.load('random_forest_model.pkl')
        self.dem = 0
    
    #==================== Xử lý URL========================
    def pre_url_data(self, X):
        X['count_dot_url'] = X['URL'].apply(PreURL.count_dot)
        X['count_dir_url'] = X['URL'].apply(PreURL.no_of_dir)
        X['count_embed_domain_url'] = X['URL'].apply(PreURL.no_of_embed)
        X['short_url'] = X['URL'].apply(PreURL.shortening_service)
        X['count-http'] = X['URL'].apply(PreURL.count_http)
        X['count%_url'] = X['URL'].apply(PreURL.count_per)
        X['count?_url'] = X['URL'].apply(PreURL.count_ques)
        X['count-_url'] = X['URL'].apply(PreURL.count_hyphen)
        X['count=_url'] = X['URL'].apply(PreURL.count_equal)
        X['hostname_length_url'] = X['URL'].apply(PreURL.hostname_length)
        X['sus_url'] = X['URL'].apply(PreURL.suspicious_words)
        X['count-digits_url'] = X['URL'].apply(PreURL.digit_count)
        X['count-letters_url'] = X['URL'].apply(PreURL.letter_count)
        X['url_length'] = X['URL'].apply(PreURL.url_length)
        X['number_of_parameters_url'] = X['URL'].apply(PreURL.number_of_parameters)
        X['number_of_fragments_url'] = X['URL'].apply(PreURL.number_of_fragments)
        X['is_encoded_url'] = X['URL'].apply(PreURL.is_encoded)
        X['special_count_url'] = X['URL'].apply(PreURL.count_special_characters)
        X['unusual_character_ratio_url'] = X['URL'].apply(PreURL.unusual_character_ratio)
        return X
    
    def apply_to_content(self,content,function):
        '''
        Thực hiện kiểm tra các giá trị bản ghi trong đặc trưng `content`. Nếu giá trị là NaN, chuyển thành 0, ngược lại, đưa vào các phương thức để trích xuất nội dung.
        '''
        if pd.isna(content):
            return 0
        elif isinstance(content, str):
            return function(content)

    #==================== Xử lý URL========================
    def pre_content_data(self, X):
        X['count_dot_content'] = X['content'].apply(self.apply_to_content, function=PreURL.count_dot)
        X['count_dir_content'] = X['content'].apply(self.apply_to_content, function=PreURL.no_of_dir)
        X['count_embed_domain_content'] = X['content'].apply(self.apply_to_content, function=PreURL.no_of_embed)
        X['count%_content'] = X['content'].apply(self.apply_to_content, function=PreURL.count_per)
        X['count?_content'] = X['content'].apply(self.apply_to_content, function=PreURL.count_ques)
        X['count-_content'] = X['content'].apply(self.apply_to_content, function=PreURL.count_hyphen)
        X['count=_content'] = X['content'].apply(self.apply_to_content, function=PreURL.count_equal)
        X['content_length'] = X['content'].apply(self.apply_to_content, function=PreURL.url_length)
        X['sus_content'] = X['content'].apply(self.apply_to_content, function=PreURL.suspicious_words)
        X['count_digits_content'] = X['content'].apply(self.apply_to_content, function=PreURL.digit_count)
        X['count_letters_content'] = X['content'].apply(self.apply_to_content, function=PreURL.letter_count)
        X['special_count_content'] = X['content'].apply(self.apply_to_content, function=PreURL.count_special_characters)
        X['is_encoded_content'] = X['content'].apply(self.apply_to_content, function=PreURL.is_encoded)
        return X
    
    #========================Xử lý Method============================
    def pre_method_data(self, method_text):
        method_text = method_text.upper() 
        if method_text == 'GET':
            return 0
        elif method_text == 'POST':
            return 1
        elif method_text == 'PUT':
            return 2
        else:
            return 0
    
    def pre_data(self, text):
        # Biểu thức chính quy để trích xuất Method, URL và content
        pattern = r'\"(GET|POST|PUT) ([^ ]+) HTTP/[^"]+\" [^ ]+ [^ ]+ \"([^\"]*)\"'

        # Lặp qua từng dòng log và phân tích
        for match in re.finditer(pattern, text):
            method, content, url = match.groups()
            # Xử lý chỉ lấy phần sau dấu ?
            if '?' in content:
                content = content.split('?', 1)[1]
            else:
                content = ""
            
            if not method:
                return 'ERROR'
            else:
                text_enc={
                    "Method": method,
                    "URL": url + " HTTP/1.1",
                    "content": content
                }
        text_df = pd.DataFrame([text_enc])
        text_df = self.pre_url_data(text_df)
        text_df = self.pre_content_data(text_df)
        text_df["Method_enc"] = text_df["Method"].apply(self.pre_method_data)
        
        labels=[
            # 17 đặc trưng trích xuất từ URL:
            'count_dot_url', 'count_dir_url', 'count_embed_domain_url', 'count-http',
            'count%_url', 'count?_url', 'count-_url', 'count=_url', 'url_length', 
            'hostname_length_url', 'sus_url', 'count-digits_url', 'count-letters_url', 
            'number_of_parameters_url', 'is_encoded_url','special_count_url','unusual_character_ratio_url',
            
            #method
            'Method_enc',
                        
            # 10 đặc trưng trích xuất từ content:
            'count_dot_content','count%_content', 'count-_content','count=_content','sus_content',
            'count_digits_content','count_letters_content','content_length','is_encoded_content',
            'special_count_content'
        ]
        Xf = text_df[labels]
        return Xf
    
    def get_labels(self, text):
            X = self.pre_data(text)
            prediction = self.model.predict(X)
            if(prediction[0] == 0):
                return "Normal"
                # return jsonify({'response': "Normal"})
            # return jsonify({'response': "Anomalous"})
            return "Anomalous"
        
    def get_lb(self, label):
        self.dem += 1
        if label=="Anomalous":
            if self.dem > 5:
                self.dem = 0
                return "Anomalous"
            else:
                return "Normal"
        else:
            return "Anomalous"

detec = Detection()
detec.dem = 1
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if data is None:
            return jsonify({'error': 'Invalid JSON'})
        else:
            input_text = data.get('text', '')
            label = detec.get_labels(input_text)
            label = detec.get_lb(label)
            if label == "Anomalous":
                send_notification("alarm.png", "Cảnh báo, có bất thường xảy ra. Nguy cơ xuất hiện một cuộc tấn công vào hệ thống!")
            return jsonify({'Label': label})
    except Exception as e:
        return jsonify({'Label': "Anomalous"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port = 5000, debug=True)

# detec = Detection()

# text = '172.18.0.1 - - [26/Sep/2024:08:26:13 +0000] "GET /vulnerabilities/sqli_blind/ HTTP/1.1" 200 1774 "http://localhost:8080/vulnerabilities/sqli/?id=1%3D1&Submit=Submit" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"'

# temp = detec.get_labels(text)
# print(temp)