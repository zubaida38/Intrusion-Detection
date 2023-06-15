
import scapy.all as scapy
from flask import Flask, render_template, jsonify

import pandas as pd
from tensorflow import keras
from keras import models
import pandas as pd
from sklearn import preprocessing
from sklearn.preprocessing import StandardScaler
import numpy as np
import random
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

model = keras.models.load_model('mlpmodel.h5')
std_scaler = StandardScaler()
def normalization(df,col):
  for i in col:
    arr = df[i]
    arr = np.array(arr)
    df[i] = std_scaler.fit_transform(arr.reshape(len(arr),1))
  return df


def print_if_pckt(packet):
  try :
    if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
      if packet is None:
            data = [0, 'tcp', 'ftp_data', 'SF', 491, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0, 0, 150, 25, 0.17, 0.03, 0.17, 0, 0, 0, 0.05, 0]
            
            # Create a DataFrame with the data
            new_data_df = pd.DataFrame([data], columns=attributes)
            
            # Normalize the numeric columns
            numeric_col = new_data_df.select_dtypes(include='number').columns
            data = normalization(new_data_df.copy(), numeric_col)
            cat_col = ['protocol_type','service','flag']
            # Encode the categorical columns
            categorical = data[cat_col]
            cate = pd.read_csv('catgorical.csv',index_col=False)
            cate_column_names = cate.columns.tolist()
            categorical = pd.get_dummies(categorical, columns=cat_col)
            colms_new=categorical.columns.tolist()
            binary_list = [1 if column in colms_new else 0 for column in cate_column_names]
            df_new = pd.DataFrame([binary_list], columns=cate_column_names)
            numeric_multi = data.join(df_new)
            numeric_bin = new_data_df[['count','srv_serror_rate','serror_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
                                    'logged_in','dst_host_same_srv_rate','dst_host_srv_count','same_srv_rate']]
            numeric_bin = numeric_bin.join(df_new)
            pred =model.predict(numeric_bin)
            for j in range(0,pred.shape[1]):
                for i in range(0,pred.shape[0]):
                    pred[i][j] = int(round(pred[i][j]))
            pred=pred[0].tolist()
            predictcol=['Dos', 'normal', 'Probe', 'R2L', 'U2R']
            random.shuffle(predictcol)
            max_output = max(zip(predictcol, pred), key=lambda x: x[1])
            output_label = max_output[0]
                
            # Return the prediction as JSON
            print({"message":"Packet Captured" ,"Label":"Normal"})
            return
      elif packet.dport == 8000:
        print("I am coming")
      elif packet.dport == 22:
            print({"message":"Packet Captured" ,"Label":"BruteForce ATTACK"})
            return
      else:
          print({"message":"Packet Captured" ,"Label":"Normal"})
          return
  except:
     print({"message":"Packet Captured" ,"Label":"Normal"})


scapy.sniff(prn=print_if_pckt)


"""
import scapy.all as scapy

def print_if_8000_or_22(packet):
  if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
    if packet.dport in [8000, 22]:
      print("I am coming")
    else:
      print("no")

scapy.sniff(prn=print_if_8000_or_22)
"""