import streamlit as st
import pandas as pd
import joblib

st.set_page_config(
    page_title="Network Anomaly Detector",
    page_icon="🌐",
    layout="centered",
    initial_sidebar_state="expanded"
)

st.sidebar.title("🔍 Navigation")
menu = st.sidebar.radio(
    "**Go To**",
    ["🏠 Home", "ℹ️ About" ,"🧪Start Testing"]
)

if menu == "🏠 Home":
    st.title("🌐 Network Anomaly Detector")
    st.markdown(
        """
        Welcome to the **Network Anomaly Detector** 👋  
        This project aims to detect **suspicious or malicious network traffic**  
        using a **Machine Learning-based approach**.

        Our goal is to enhance the security of network systems  
        by identifying unusual traffic behavior in real time.
        """
    )

elif menu == "ℹ️ About":
    st.title("ℹ️ About the Project")

    st.markdown(
        """
        ### ⚙️ Project Overview
        This project is designed to **detect network anomalies** such as suspicious or malicious activities in network traffic.  
        The system classifies incoming network data as either **Normal** or **Suspicious**, helping to identify potential threats.

        ### 🧠 Model Details
        - **Algorithm Used:** `Random Forest Classifier  
        - **Dataset:** CICIDS2017 (Cleaned and Preprocessed)  
        - **Programming Language:** Python  
        - **Libraries:** pandas, numpy, scikit-learn, and streamlit  
        - **Cybersecurity Tool:** TShark for packet capturing

        The model was trained using multiple extracted network features like flow duration, packet length statistics, forward/backward packet counts, and flag/timing parameters.

        ### 🚀 Functionality
        - Users can test the system **manually** by entering network parameters.  
        - It also supports **real-time detection** by analyzing CSV files generated through **TShark**.  
        - Predictions are displayed as **Normal Traffic** or **Suspicious Activity**.

        ### 🔮 Future Scope
        - Integrate **Deep Learning models** (like LSTM or CNN) for higher detection accuracy.  
        - Implement **automatic packet capture** directly from live networks.  
        - Develop **alert systems** to notify administrators about detected anomalies in real time.  
        - Extend it to an **IPS(Intrusion Protection System)**.
        """
    )
elif menu == "🧪Start Testing":
    test_mode = st.sidebar.radio("Choose Test Mode:",["Manual Testing", "Real-Time Testing"])
    if (test_mode == "Manual Testing"):
        st.title("Manual Testing Selected")
        uploaded_file = st.file_uploader("📂 Upload a CSV file for testing", type=["csv"])

        if uploaded_file is not None:
            df = pd.read_csv(uploaded_file, header = 0)
            st.success("✅ File uploaded successfully!")
    
            st.subheader("📊 Uploaded Data Preview:")
            st.dataframe(df.head())
        else:
            st.info("Please upload a CSV file to begin testing.")
        if (st.button("Predict Now")):
            try:
            
                model = joblib.load(r"E:\Anomaly Detector\models\Random_forest_model.pkl") 
                scaler = joblib.load(r"E:\Anomaly Detector\models\scaler.pkl")
            
                input_data = pd.to_numeric(df.iloc[0], errors='coerce').values.reshape(1, -1)
                input_scaled = scaler.transform(input_data)
            
                prediction = model.predict(input_scaled)[0]

            
                st.subheader("📃Prediction Result:")
                if(prediction == 0):
                    prediction = "Botnet Attack"
                elif(prediction == 1):
                    prediction = "Brute Force Attack"
                elif(prediction == 2):
                    prediction = "DDoS Attack"
                elif(prediction == 3):
                    prediction = "Dos"
                elif(prediction == 4):
                    prediction ="Normal Traffic"
                elif(prediction == 5):
                    prediction = "portScan Attack"
                elif(prediction == 6):
                    prediction = "Web Attack"
                if(prediction == "Normal Traffic"):
                    st.success(f"🔮The model prediction is: **{prediction}**")
                else:
                    st.error(f"🔮The model prediction is: **{prediction}**")

            except Exception as e:
                st.error(f"❌ Error during prediction: {e}")

    elif (test_mode == "Real-Time Testing"):
        st.title("Real-Time Testing Selected")
