#Network Anomaly Detector
Machine Learning–based Real-Time Threat Detection System

A lightweight yet powerful ML model that detects malicious network activity (DDoS attack, DoS, Brute Force, Bots, Web Attacks, etc) using preprocessing, model training, UI testing, and real-time packet monitoring.

#Features

ML-based anomaly classification

Data preprocessing and dtype correction

Metrics visualization (Accuracy, F1, Confusion Matrix)

Manual traffic testing through UI

Real-time packet monitoring

Detects 6 Types of anomalies(Brute force, Bots, DoS, DDoS, Port Scanning, Web Attacks) or Normal Traffic

#Folder Structure
<img align = "center" width="373" height="522" alt="Screenshot 2025-11-28 122848" src="https://github.com/user-attachments/assets/60b61756-56f7-4a5e-91ad-4dcbe3c2a943" />

#Model Performance
<img align = "center" width="373" height="522" alt="Screenshot 2025-11-28 122848" src="https://github.com/user-attachments/assets/7ffe75b5-858f-44e9-afaf-224c3457d9b0" />


#User Interface
<img align = "center" width="1586" height="656" alt="Screenshot 2025-11-07 221928" src="https://github.com/user-attachments/assets/375fc08a-32b9-4dcc-8934-e98fbb09d9c3" />

Anomaly Detector offers 2 types of testing - Manual testing and Real-Time testing
#Manual Testing
Manual Testing offers uploadig a file with captured packets/data, then passing it to the model to make predictions.

#Normal Traffic Prediction - Manual Testing
<img width="1615" height="964" alt="Screenshot 2025-11-07 234331" src="https://github.com/user-attachments/assets/d22dd991-e0b6-4f55-b6f4-46576b3b9aad" />


#Malicious Traffic Prediction(here DDoS) - Manual Testing
<img width="1622" height="977" alt="Screenshot 2025-11-07 234350" src="https://github.com/user-attachments/assets/9b89d3a1-ecd8-4c3d-92bd-0d4daa28ac89" />

#Real-Time Network Detection
In this Testing - ANOMALY DETECTOR  capture the live packets of the system using Tshark(a commandline Wireshark), then it generates a csv which is then preprocessed automatically in the real-time and then is passed to the model to make predictions.
I have captured a normal traffic using real-time testing feature of anomaly detector.

<img align = "center" width="1825" height="956" alt="Screenshot 2025-11-28 082130" src="https://github.com/user-attachments/assets/659539c2-9a5a-4389-8e70-dcdc9a5c1bfc" />

Here is the .csv file of the live captured packets 
<img align= "center" width="1859" height="761" alt="Screenshot 2025-11-28 125847" src="https://github.com/user-attachments/assets/7c8a5701-f783-4259-b658-1309e2a56a8d" />


#Tech Stack

Python

pandas, numpy

scikit-learn

streamlit

Tshark

#How to Run
1. Install dependencies
pip install -r requirements.txt

2. Train the model
python src/model_training.py

3. Start the UI
python ui/app.py

4. Run real-time detection

#Contributing

Pull requests are welcome. Open an issue for improvements or suggestions.

#Developer

Abhay Chauhan
BTech CSE • ML & Cybersecurity Enthusiast
