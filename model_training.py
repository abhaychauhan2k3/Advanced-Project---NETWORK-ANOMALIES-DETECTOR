import pandas as pd

# loading dataset 
df = pd.read_csv(r"E:\Anomaly Detector\data\cicids2017_cleaned.csv")
'''print(df.head())
print("Shape :", df.shape)
print("Columns : ",df.columns)
print(df['Attack Type'].value_counts())'''

#splitting the dataset into features and labels
X = df.drop(columns=['Attack Type'])
y = df['Attack Type']
'''print("Features shape :", X.shape)
print("Labels shape :", y.shape)       
print("unique labels: ", y.unique())'''

#encode the labels (Attack Type)
from sklearn.preprocessing import LabelEncoder

le = LabelEncoder()
y_encoded = le.fit_transform(y)
'''print("label encoded successfully")
print("Encoded labels: ", y_encoded)
#checking the mapping of original labels to encoded labels
label_mapping = dict(zip(le.classes_, range(len(le.classes_))))
print("Label mapping: ", label_mapping)'''

#splitting the dataset into training and testing sets
from sklearn.model_selection import train_test_split        
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)
'''print("Training features shape: ", X_train.shape)    
print("Testing features shape: ", X_test.shape)'''

#feature scaling
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)  
X_test_scaled = scaler.transform(X_test)
print("Feature scaling completed")

#training the model
from sklearn.ensemble import RandomForestClassifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf_model.fit(X_train_scaled, y_train)
print("Model training completed")

#evaluating the model
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
y_pred = rf_model.predict(X_test_scaled)
train_acc = rf_model.score(X_train_scaled, y_train)
test_acc = accuracy_score(y_test, y_pred)
print("Training Accuracy: ", round(train_acc* 100 , 2), "%")
print("Testing Accuracy: ", round(test_acc* 100 , 2), "%")

#detailed classification report
print("Classification Report: \n", classification_report(y_test, y_pred))
#confusion matrix
print("Confusion Matrix: \n", confusion_matrix(y_test, y_pred))

#saving the model and scaler
import joblib
joblib.dump(rf_model, r'E:\Anomaly Detector\models\Random_forest_model.pkl')
joblib.dump(scaler, r'E:\Anomaly Detector\models\scaler.pkl')
print("Model and scaler saved successfully")