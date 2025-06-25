# 🐙 Locktopus - Ultimate Password Assistant

**Locktopus** is a powerful GUI-based Python tool that helps users analyze, validate, and improve the strength of their passwords. Designed with security and usability in mind, it offers real-time feedback, hash generation, breach checks, and advanced pattern detection — all wrapped in a basic, themed interface.


---

## 🔐 Features

- **Real-time Password Analysis**
  - Entropy calculation
  - Strength scoring & meter
  - Visual feedback with emojis and color coding

- **Rule-Based Validation**
  - Customizable password policies (length, case, digits, symbols)
  - Regex checks (must match / must not match)
  - Detection of dictionary words, context words, and common keyboard patterns

- **Advanced Pattern Recognition**
  - Repeated characters
  - Repeated substrings
  - Keyboard sequences

- **Breach Check Integration**
  - Checks passwords against known breaches via [HaveIBeenPwned](https://haveibeenpwned.com/Passwords) API (k-anonymity model)

- **Hash Generator**
  - Supports SHA1, SHA256, SHA512, and MD5

- **Multi-theme UI**
  - Light, Dark, Brown, and Beige themes
  - Seamless theme toggle button

---

## 💻 Technologies Used

- **Python 3**
- **Tkinter** for GUI
- **Requests** for breach API
- **Threading** for responsive checks
- **Hashlib**, **math**, **re**, and **string** for core logic

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/locktopus.git
cd locktopus
````

### 2. Install Dependencies

Only one dependency outside the standard library is used:

```bash
pip install requests
```

### 3. Run the App

```bash
python locktopus.py
```

---

## ⚙️ Configuration

You can easily modify password rules in the `config` dictionary:

```python
config = {
    "min_length": 12,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_symbol": True,
    "max_repeating_chars": 3,
    "max_repeating_substring": 4,
    "must_match_regex": "",
    "must_not_match_regex": "password|admin|1234",
    "disallowed_words": {"siddharth", "gmail", "123"},
    "guesses_per_second": 1e9
}
```


## 🧠 Future Improvements

* Export password analysis as PDF
* Add password generator with advanced options
* Support for zxcvbn-like scoring
* GUI animations for feedback
* Store policy profiles (work, personal, etc.)

---

## 🛡️ Disclaimer

This tool is for **educational** and **personal productivity** use. Never enter real passwords unless you're comfortable — breach check uses a **safe k-anonymity API model**, but local use is recommended.


---

## 🧑‍💻 Author

**Siddharth Rai**
🔗 [LinkedIn](https://www.linkedin.com/in/siddharthrai1) | 🐙 [GitHub](https://github.com/Sidd-Rai)

---

## ⭐️ Star this repo

If you found this project useful, consider giving it a ⭐️ and sharing it with others!


