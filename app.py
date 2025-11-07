import streamlit as st
import pandas as pd
import joblib

# ===============================================================
# PAGE CONFIG
# ===============================================================
st.set_page_config(page_title="Network Anomaly Detector", layout="wide")

st.title("🧠 Network Anomaly Detector (Full Feature Mode)")
st.markdown("""
Upload a `.csv` file captured from **TShark** or your preprocessed dataset.  
This version uses **all 53 features** for highly accurate traffic anomaly detection.
""")

# ===============================================================
# LOAD MODEL (CACHED)
# ===============================================================
@st.cache_resource
def load_model():
    model = joblib.load(r"E:\Anomaly Detector\models\Random_forest_model.pkl")
    return model

model = load_model()

# ===============================================================
# LOAD REFERENCE DATA TO GET FEATURE ORDER
# ===============================================================
reference_data = pd.read_csv(r"E:\Anomaly Detector\data\cicids2017_cleaned.csv")
model_features = [col for col in reference_data.columns if col != "Attack Type"]

# ===============================================================
# FILE UPLOAD SECTION
# ===============================================================
uploaded_file = st.file_uploader("📂 Upload your CSV file (with network traffic features)", type=["csv"])

if uploaded_file is not None:
    try:
        df = pd.read_csv(uploaded_file)
        st.success(f"✅ Successfully loaded file with {df.shape[0]} rows and {df.shape[1]} columns.")
        st.dataframe(df.head())

        # ===============================================================
        # VERIFY FEATURES
        # ===============================================================
        missing_features = [f for f in model_features if f not in df.columns]
        extra_features = [f for f in df.columns if f not in model_features]

        if missing_features:
            st.error(f"⚠️ Missing required features in uploaded CSV: {missing_features}")
        else:
            st.info(f"📋 Using {len(model_features)} features for prediction.")
            if extra_features:
                st.warning(f"ℹ️ Ignoring extra columns: {extra_features}")

            # Use only model-relevant features
            X = df[model_features]

            # ===============================================================
            # PREDICTION
            # ===============================================================
            if st.button("🔍 Predict Anomalies"):
                with st.spinner("Analyzing traffic..."):
                    predictions = model.predict(X)

                df["Prediction"] = ["Normal" if p == 0 else "Attack" for p in predictions]

                # Count results
                attack_count = (df["Prediction"] == "Attack").sum()
                normal_count = (df["Prediction"] == "Normal").sum()

                # ===============================================================
                # DISPLAY RESULTS
                # ===============================================================
                st.subheader("📊 Prediction Summary")
                st.write(f"✅ Normal Traffic: **{normal_count}**")
                st.write(f"🚨 Attacks Detected: **{attack_count}**")

                # Highlight predictions
                def highlight_predictions(row):
                    color = "background-color: #ffcccc" if row["Prediction"] == "Attack" else "background-color: #ccffcc"
                    return [color] * len(row)

                st.subheader("🔎 Sample Prediction Results")
                st.dataframe(df.head(30).style.apply(highlight_predictions, axis=1))

                # ===============================================================
                # DOWNLOAD RESULT
                # ===============================================================
                csv = df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="📥 Download Full Prediction Results",
                    data=csv,
                    file_name="predicted_results_full.csv",
                    mime="text/csv"
                )

    except Exception as e:
        st.error(f"❌ Error while processing file: {e}")

else:
    st.info("📤 Please upload a CSV file to begin analysis.")