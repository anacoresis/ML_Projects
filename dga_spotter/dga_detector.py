import pandas as pd
import math
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# 1. Synthetic Dataset (for now)
try:
    df = pd.read_csv('domains.csv')
    print(f"[*] Successfully loaded {len(df)} domains from CSV.")
except FileNotFoundError:
    print("[-] Error: domains.csv not found. Please create it first.")
    exit()

# 2. Feature Extraction
def calculate_entropy(text):
    """Calculates the randomness of a string. High entropy = very random."""
    if not text:
        return 0
    """Counter(text) counts how many times each letter appears"""
    p, lns = Counter(text), float(len(text))
    """Shannon Entropy formula"""
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def get_vowel_ratio(text):
    """Calculates the ratio of vowels to total characters."""
    if not text:
        return 0
    vowels = sum(1 for char in text if char.lower() in 'aeiou')
    return vowels / len(text)

def extract_features(domain):
    """Turns the domain string into a list of numbers for the AI."""
    # Strip the extension before analyzing
    name = str(domain).split('.')[0] 
    
    return [
        len(name),                 # Feature 1: Length
        calculate_entropy(name),   # Feature 2: Randomness
        get_vowel_ratio(name)      # Feature 3: Vowel ratio
    ]

# Apply the extraction rules to the dataset
X = list(df['domain'].apply(extract_features))
y = df['label'] # The answers

# 3. Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Train the model
print("[*] Training the DGA Detection AI...")
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# 5. Test accuracy
predictions = model.predict(X_test)
print(f"[+] Accuracy on test data: {accuracy_score(y_test, predictions) * 100}%\n")

# 6. Inference (Real-world testing)
test_domains = ["microsoft.com", "vgy789huijkm.biz", "netflix.com", "p0o9i8u7y6t5.ru"]

print("[*] Analyzing unknown domains:")
for domain in test_domains:
    features = [extract_features(domain)]
    prediction = model.predict(features)
    
    if prediction[0] == 1:
        print(f" 🚨 DGA DETECTED : {domain}")
    else:
        print(f" ✅ LEGITIMATE   : {domain}")
