# 🛡️ Phishing URL Detection System

A **Hybrid Phishing URL Detection System** that combines **Machine Learning** with **rule-based security checks** to identify malicious, deceptive, and phishing URLs in real time.

This project goes beyond basic ML models by detecting **typo-squatting**, **brand impersonation**, and **suspicious subdomains**, making it closer to real-world browser security systems.

---

## 📌 Features

- ✅ Machine Learning–based phishing detection (Random Forest)
- 🔍 Typo-squatting detection (e.g. `yutube.com` → `youtube.com`)
- 🚨 Brand impersonation detection (e.g. `wwwyoutube.com`)
- ⚠️ Suspicious subdomain detection (e.g. `ww.youtube.com`)
- 🟢 Trusted domain whitelist for high-confidence safety
- 🌐 Interactive Streamlit web interface

---

## 🧠 Detection Architecture

The system follows a **hybrid security pipeline**:

1. URL normalization & parsing
2. Trusted domain verification
3. Typo-squatting detection
4. Brand concatenation detection
5. Suspicious subdomain detection
6. Machine Learning classification

This layered approach reduces **false negatives** and improves **real-world accuracy**.

---

## 🛠️ Tech Stack

- **Programming Language:** Python 3.10
- **Machine Learning:** scikit-learn (RandomForestClassifier)
- **Web Framework:** Streamlit
- **Libraries:** pandas, numpy, python-whois
- **Model Serialization:** pickle

---

## 📂 Project Structure

```
Phising URL/
│
├── app.py                  # Streamlit application
├── feature.py              # Feature extraction logic
├── README.md               # Project documentation
├── phishing.csv            # Dataset (optional, for training)
│
├── pickle/
│   └── model.pkl           # Trained ML model
│
└── training/
    └── Phishing_URL_Detection.ipynb  # Training notebook (optional)
```

---

## 🚀 How to Run the Project

### 1️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install streamlit pandas numpy scikit-learn python-whois
```

---

### 2️⃣ Run the Streamlit App

```bash
python -m streamlit run app.py
```

The app will open in your browser at:

```
http://localhost:8501
```

---

## 🧪 Example Test Cases

| URL | Result |
|---|---|
| `www.youtube.com` | ✅ SAFE |
| `yutube.com` | ⚠️ TYPO-SQUATTING |
| `ww.youtube.com` | ⚠️ SUSPICIOUS SUBDOMAIN |
| `wwwyoutube.com` | ⚠️ BRAND IMPERSONATION |
| `paypal-login-update.com` | ⚠️ PHISHING |

---

## 📈 Model Details

- **Algorithm:** Random Forest Classifier
- **Training Platform:** Google Colab
- **Features Used:** URL length, HTTPS usage, DNS record, domain age, redirection patterns, special characters, and more
- **Model File:** `pickle/model.pkl`

The model is loaded at runtime and combined with rule-based security checks.

---

## ⚠️ Limitations

- ML models alone cannot detect all phishing patterns
- Brand-new phishing domains may evade detection temporarily
- Whitelist-based trust must be updated periodically

These limitations are mitigated using **rule-based heuristics**.

---

## 🔮 Future Enhancements

- Integration with Google Safe Browsing API
- Real-time domain reputation scoring
- Deep learning–based URL embeddings
- Browser extension version

---

## 👨‍💻 Author

**Dhruv Verma**  
© 2025

GitHub: https://github.com/vermadhruv2004

---

## 📜 License

This project is created for **academic and demonstration purposes**.

