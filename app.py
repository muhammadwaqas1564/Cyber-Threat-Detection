from flask import Flask,request,render_template,jsonify
import pickle
import numpy as np
import joblib
import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Embedding, LSTM
from tensorflow.keras.utils import to_categorical
from sklearn.preprocessing import LabelEncoder
import json
from urllib.parse import quote

MAX_SEQUENCE_LENGTH = 100

app = Flask(__name__)

def preprocess_url(url,tokenizer):
    sequences = tokenizer.texts_to_sequences([url])
    padded_sequences = pad_sequences(sequences, maxlen=MAX_SEQUENCE_LENGTH)
    return padded_sequences

def classify_url(url,tokenizer, model,label_encoder):
    feature_vector = preprocess_url(url,tokenizer)
    prediction = model.predict(feature_vector)
    predicted_label = np.argmax(prediction, axis=1)[0]
    return label_encoder.inverse_transform([predicted_label])[0]

def preprocess_input(user_input,scaler):
    # Convert the input to a NumPy array (assuming it's a list of numbers)
    input_array = np.array(user_input)

    # Reshape the array to match the model's input shape
    input_array = input_array.reshape(1, -1)

    # Scale the input using the loaded scaler
    scaled_input = scaler.transform(input_array)

    return scaled_input

# Function to make a prediction
def predict_malware(user_input,scaler,loaded_model,le):
    # Preprocess the input
    processed_input = preprocess_input(user_input,scaler)

    # Make a prediction using the loaded model
    prediction = loaded_model.predict(processed_input)

    # Convert the prediction to a class label
    predicted_class = le.inverse_transform(np.round(prediction).astype(int))[0]

    return predicted_class

@app.route('/')
def renderHome():
    return render_template('index.html')

@app.route('/phishing')
def renderPhishing():
    return render_template('phishing.html')

@app.route('/malware')
def renderMalware():
    return render_template('malware.html')

@app.route('/intrusion')
def renderIntrusion():
    return render_template('intrusion.html')

@app.route('/predict/phishing', methods=['POST'])
def predictPhishing():
    url_to_check = request.get_json().get('url')
    model = load_model('./PhishingWebsitedata/url_classifier_model.h5')
    with open('./PhishingWebsitedata/tokenizer.pkl', 'rb') as f:
        tokenizer = pickle.load(f)
    with open('./PhishingWebsitedata/label_encoder.pkl', 'rb') as f:
        label_encoder = pickle.load(f)

    result = classify_url(url_to_check,tokenizer,model,label_encoder)

    return jsonify({'url':url_to_check,'prediction':result})

@app.route('/predict/intrusion', methods=['POST'])
def predictIntrusion():
    loaded_model = tf.keras.models.load_model('./Intrusiondata/intrusion_detection_model.h5')
    with open('./Intrusiondata/scaler.pkl', 'rb') as f:
        loaded_scaler = pickle.load(f)
    with open('./Intrusiondata/label_encoder.pkl', 'rb') as f:
        loaded_label_encoder = pickle.load(f)

    data = request.get_json()
    values = list(data.values())

    input_data = np.array([values])
    scaled_input = loaded_scaler.transform(input_data)

    # Make a prediction using the loaded model
    prediction = loaded_model.predict(scaled_input)

    # Get the predicted class index
    predicted_class_index = np.argmax(prediction)

    # Convert the predicted class index to the original label
    predicted_label = loaded_label_encoder.classes_[predicted_class_index]


    return jsonify({'prediction':predicted_label})

@app.route('/predict/malware', methods=['POST'])
def predictMalware():
    loaded_model = load_model('./Malwaredata/best_model.h5')
    scaler = joblib.load('./Malwaredata/standard_scaler.pkl')
    le = joblib.load('./Malwaredata/label_encoder.pkl')

    user_input = request.get_json()
    print(user_input)
    user_input = list(user_input.values())
    predicted_class = predict_malware(user_input,scaler,loaded_model,le)

    return jsonify({'prediction':predicted_class})


if __name__ == '__main__':
    app.run()


