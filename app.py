import streamlit as st
import pickle
import os
from urllib.parse import urlparse
from difflib import SequenceMatcher

from feature import FeatureExtraction

# ------------------ Page Config ------------------
st.set_page_config(page_title="Phishing URL Detection", page_icon="🛡️", layout="centered")

# ------------------ Trusted Domains ------------------
TRUSTED_DOMAINS = [
    "youtube.com",
    "google.com",
    "facebook.com",
    "amazon.com",
]

ALLOWED_SUBDOMAINS = {
    "youtube.com": ["www", "m", "music", "studio"],
    "google.com": ["www", "mail", "drive", "accounts", "maps"],
    "facebook.com": ["www", "m"],
    "amazon.com": ["www"],
}

# ------------------ Helper Functions ------------------
def is_typosquatting(domain, trusted_domains, threshold=0.85):
    # 1. Misspelling check (yutube → youtube)
    for trusted in trusted_domains:
        similarity = SequenceMatcher(None, domain, trusted).ratio()
        if similarity >= threshold and domain != trusted:
            return True, trusted, "Typo-squatting (misspelling)"

    # 2. Brand concatenation check (wwwyoutube, securepaypal)
    for trusted in trusted_domains:
        brand = trusted.split(".")[0]
        if brand in domain and domain != trusted:
            if domain.replace(".", "").endswith(brand):
                return True, trusted, "Brand impersonation (missing dot)"

    return False, None, None


def is_suspicious_subdomain(subdomain, domain):
    allowed = ALLOWED_SUBDOMAINS.get(domain, [])

    if subdomain in allowed:
        return False, None

    similarity = SequenceMatcher(None, subdomain, "www").ratio()
    if similarity >= 0.7:
        return True, "Looks like a fake www subdomain"

    phishing_words = ["login", "secure", "verify", "update", "account"]
    if any(word in subdomain for word in phishing_words):
        return True, "Suspicious keyword in subdomain"

    return False, None


# ------------------ Load Model ------------------
MODEL_PATH = os.path.join("pickle", "model.pkl")

if not os.path.exists(MODEL_PATH):
    st.error("Model file not found. Please ensure pickle/model.pkl exists.")
    st.stop()

try:
    with open(MODEL_PATH, "rb") as file:
        model = pickle.load(file)
except Exception as e:
    st.error("Model loading failed. Please check dependencies.")
    st.stop()


# ------------------ UI ------------------
st.markdown("<h1 style='text-align:center;'>🛡️ Phishing URL Detection</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align:center;'>Machine Learning based URL safety analysis</p>", unsafe_allow_html=True)

url = st.text_input("🌐 Enter Website URL", placeholder="example.com")

if st.button("🔍 Check Website"):
    if not url:
        st.warning("Please enter a URL")
        st.stop()

    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    host = parsed.netloc.lower()

    if host.startswith("www."):
        host = host[4:]

    parts = host.split(".")

    # ------------------ Trusted Domain Check ------------------
    if host in TRUSTED_DOMAINS:
        st.success("✅ This website is SAFE")
        st.write("Confidence: Very High (Trusted Domain)")
        st.stop()

    # ------------------ Typo-squatting / Brand Impersonation ------------------
    is_typo, original, reason = is_typosquatting(host, TRUSTED_DOMAINS)
    if is_typo:
        st.error("⚠️ Possible TYPO / BRAND IMPERSONATION detected!")
        st.write(f"Resembles: **{original}**")
        st.write(f"Reason: {reason}")
        st.stop()

    # ------------------ Suspicious Subdomain Detection ------------------
    if len(parts) > 2:
        subdomain = parts[0]
        domain = ".".join(parts[-2:])

        if domain in TRUSTED_DOMAINS:
            suspicious, reason = is_suspicious_subdomain(subdomain, domain)
            if suspicious:
                st.warning("⚠️ Suspicious subdomain detected")
                st.write(f"Subdomain: **{subdomain}.{domain}**")
                st.write(f"Reason: {reason}")
                st.stop()

    # ------------------ ML Prediction ------------------
    features = FeatureExtraction(url).getFeaturesList()
    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0]

    if prediction == 1:
        st.success("✅ This website is SAFE")
        st.write(f"Confidence: {probability[1]*100:.2f}%")
    else:
        st.error("⚠️ This website is PHISHING")
        st.write(f"Confidence: {probability[0]*100:.2f}%")

# ------------------ Footer ------------------
st.markdown("""
<div class="footer">
<hr>
Phishing URL Detection using Machine Learning<br>
Academic / Demo Project<br><br>
© 2025 DHRUV VERMA<br>
<a href="https://github.com/vermadhruv2004" target="_blank" style="color:#4da6ff; text-decoration:none;">
GitHub
</a>
</div>
""", unsafe_allow_html=True)
