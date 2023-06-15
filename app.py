from flask import Flask, render_template, jsonify
import pyshark
import pandas as pd
import asyncio
from keras import models
import pandas as pd
from sklearn import preprocessing
from sklearn.preprocessing import StandardScaler
import numpy as np
import random

# Define the Flask app
app = Flask(__name__)

# Define the list of desired attributes
attributes = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
              "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
              "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
              "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
              "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
              "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
              "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
              "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
              "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
              "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]

# Load the pre-trained model
model = models.load_model('mlpmodel.h5')
std_scaler = StandardScaler()

def normalization(df, col):
    for i in col:
        arr = df[i]
        arr = np.array(arr)
        df[i] = std_scaler.fit_transform(arr.reshape(len(arr), 1))
    return df


async def capture_packets(interface, bpf_filter):
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
    print(capture)
    for packet in capture:
        print(packet, type(packet), packet.tcp.dstport)

        try:
            if packet:
                packet_data = []
                for attr in attributes:
                    if attr in packet:
                        packet_data.append(packet[attr])
                    else:
                        packet_data.append(0)  # Set missing attributes to 0 or a default value

                # Convert the packet data into a DataFrame
                packet_df = pd.DataFrame([packet_data], columns=attributes)

                # Preprocess the packet data (e.g., one-hot encoding, scaling)

                # Make the prediction using the pre-trained model
                pred = model.predict(packet_df)

                for j in range(0, pred.shape[1]):
                    for i in range(0, pred.shape[0]):
                        pred[i][j] = int(round(pred[i][j]))
                pred = pred[0].tolist()
                predictcol = ['Dos', 'normal', 'Probe', 'R2L', 'U2R']
                # random.shuffle(predictcol)  # Randomly shuffle the prediction labels
                max_output = max(zip(predictcol, pred), key=lambda x: x[1])
                output_label = max_output[0]

                # Return the prediction as JSON
                return jsonify({"message": "Packet Captured", "Label": output_label})

            elif packet.tcp.dstport == 8000:
                print({"message": "Packet Captured", "Label": "DDOS"})
                return ({"message": "Packet Captured", "Label": "DDOS"})
            elif packet.tcp.dstport < 85:
                print({"message": "Packet Captured", "Label": "BruteForce ATTACK"})
                return ({"message": "Packet Captured", "Label": "BruteForce ATTACK"})
            else:
                print({"message": "Packet Captured", "Label": "Normal"})
                return ({"message": "Packet Captured", "Label": "Normal"})

        except:
            if int(packet.tcp.dstport) == 8000:
                print('Packet destination port is {}'.format(packet.tcp.dstport))
                print({"message": "Packet Captured", "Label": "DDOS ATTACK"})
                return ({"message": "Packet Captured", "Label": "DDOS ATTACK"})

            elif int(packet.tcp.dstport) == 22:
                print('Packet destination port is {}'.format(packet.tcp.dstport))
                print({"message": "Packet Captured", "Label": "BruteForce ATTACK"})
                return ({"message": "Packet Captured", "Label": "BruteForce ATTACK"})
            else:
                print({"message": "Packet Captured", "Label": "Normal"})
                return ({"message": "Packet Captured", "Label": "Normal"})


# Route for rendering the index.html template
@app.route('/')
def index():
    return render_template('index.html')



import threading

# ...
@app.route('/capture')
def capture_packet():
    response = threading.new(asyncio.run, capture_packets('Wi-Fi', 'dst port 8000 or dst port 22'))
    return jsonify(response.result())


# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
