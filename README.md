# Live-Threats-Detection
NSL KDD is a project focused on network security and data analysis. The project aims to develop a web application that utilizes machine learning techniques, specifically TensorFlow and Keras, to analyze network traffic patterns and detect potential security threats. The application will leverage a Raspberry Pi device, known for its versatility and compact size, to monitor network activity and collect relevant data.

The attributes to be considered for analysis include various parameters such as duration, protocol type, service, flag, source bytes, destination bytes, and many more. These attributes provide valuable information about network connections and help in identifying patterns associated with potential security breaches.

By employing machine learning algorithms, the NSL KDD project seeks to detect anomalous behaviors such as brute force attacks on port 22 and distributed denial-of-service (DDoS) attacks on port 8000. These attacks can pose significant risks to network infrastructure and disrupt the normal functioning of systems.

Through the analysis of network traffic, the web application will provide insights into the presence of suspicious activities, allowing administrators to take appropriate measures to safeguard their network and mitigate potential threats. The utilization of TensorFlow and Keras frameworks will enable the development of accurate and efficient models for real-time threat detection and classification.

The NSL KDD project strives to enhance network security by leveraging the power of machine learning and intelligent data analysis, empowering organizations to proactively protect their systems from unauthorized access and malicious activities.


Certainly! In the NSL KDD project, a wide range of features are utilized to analyze network traffic and identify potential security threats. The following features are considered:

- "duration": Represents the length of time of a particular network connection.
- "protocol_type": Indicates the protocol used in the network connection, such as TCP or UDP.
- "service": Refers to the specific service associated with the network connection, such as HTTP or FTP.
- "flag": Represents the status or flag of the network connection, providing information about its state.
- "src_bytes" and "dst_bytes": Denote the number of source bytes and destination bytes transferred in the network connection, respectively.
- "land": Indicates whether the source and destination IP addresses and ports are the same, which may indicate a potential attack.
- "wrong_fragment": Represents the number of incorrect or malformed packets within a fragmented network connection.
- "urgent": Denotes the number of urgent packets within a network connection.
- "hot": Indicates the number of "hot" indicators or access to popular services.
- "num_failed_logins": Represents the number of failed login attempts.
- "logged_in": Indicates whether the login was successful or not.
- "num_compromised": Refers to the number of compromised hosts involved in the network connection.
- "root_shell" and "su_attempted": Denote whether a root shell was obtained or a superuser (su) attempt was made.
- "num_root": Represents the number of root accesses.
- "num_file_creations", "num_shells", "num_access_files": Indicate the number of file creations, shells spawned, and access files created, respectively.
- "num_outbound_cmds": Represents the number of outbound commands from the source to the destination.
- "is_host_login" and "is_guest_login": Denote whether the login was performed as a host or guest.
- "count" and "srv_count": Represent the number of connections to the same host and the same service, respectively.
- "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate": Indicate the error rates for various connections and services.
- "same_srv_rate" and "diff_srv_rate": Denote the rates of connections to the same service and different services, respectively.
- "srv_diff_host_rate": Represents the rate of connections to different hosts using the same service.
- "dst_host_count" and "dst_host_srv_count": Represent the number of connections to the same destination host and the number of connections to the same destination service, respectively.
- "dst_host_same_srv_rate" and "dst_host_diff_srv_rate": Indicate the rates of connections to the same destination service and different destination services, respectively.
- "dst_host_same_src_port_rate" and "dst_host_srv_diff_host_rate": Denote the rates of connections from the same source port to the same destination port and the rate of connections from the same source port to different destination hosts, respectively.
- "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate": Indicate the error rates for connections to the destination host and the destination service.

These features play a crucial role in analyzing network traffic patterns, detecting anomalies, and identifying potential security threats within the NSL KDD project.


Features=[ "duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"]
