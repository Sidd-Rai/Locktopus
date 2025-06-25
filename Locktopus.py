import tkinter as tk
from tkinter import ttk, messagebox
import string, math, re, hashlib, requests
from threading import Thread

# ========== CONFIGURATION ==========
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
import re
from datetime import datetime

def detect_advanced_patterns(password):
    pw = password.lower()
    patterns = []

    # 1. Repeated characters (e.g., "aaa", "1111")
    if re.search(r'(.)\1{2,}', pw):
        patterns.append("🔁 Repeated characters")

    # 2. Repeated substrings (e.g., "abcabcabc")
    for size in range(2, len(pw) // 2 + 1):
        chunk = pw[:size]
        if chunk * (len(pw) // size) == pw:
            patterns.append(f"♻ Repeated substring: '{chunk}'")
            break

    # 3. Palindromes (e.g., "racecar", "abba")
    if pw == pw[::-1] and len(pw) > 4:
        patterns.append("🔄 Palindrome pattern")

    # 4. Keyboard sequences
    keyboard_seqs = ['qwerty', 'asdf', 'zxcv', '1qaz', '2wsx']
    if any(seq in pw for seq in keyboard_seqs):
        patterns.append("⌨️ Common keyboard pattern")

    # 5. Alphabetic sequences
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    for i in range(len(pw) - 2):
        chunk = pw[i:i+3]
        if chunk in alphabet or chunk in alphabet[::-1]:
            patterns.append("🔤 Alphabetic sequence")
            break

    # 6. Numeric sequences
    numbers = "0123456789"
    for i in range(len(pw) - 2):
        chunk = pw[i:i+3]
        if chunk in numbers or chunk in numbers[::-1]:
            patterns.append("🔢 Numeric sequence")
            break

    # 7. Date or year patterns
    if re.search(r'(19\d{2}|20[0-2]\d)', pw):
        patterns.append("📅 Year pattern (e.g. 1999, 2023)")
    if re.search(r'\d{2}[/-]\d{2}[/-]\d{4}', pw) or re.search(r'\d{8}', pw):
        patterns.append("📆 Date-like pattern (e.g. 25062025 or 25/06/2025)")

    # 8. Common usernames/admins
    common_words = {"admin", "guest", "root", "user", "test"}
    if any(word in pw for word in common_words):
        patterns.append("🧑‍💻 Common placeholder/admin words")

    # 9. Simple regex categories
    if re.fullmatch(r'[a-zA-Z]+', pw):
        patterns.append("🅰️ Only letters")
    if re.fullmatch(r'\d+', pw):
        patterns.append("🔢 Only digits")
    if re.fullmatch(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]+', pw):
        patterns.append("🔣 Only symbols")

    return patterns

def load_dictionary(path="./dictionary.txt"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        print("⚠️ dictionary.txt not found. Continuing with empty dictionary.")
        return set()

DICTIONARY = load_dictionary()

theme = {
    "light": {
        "bg": "#ffffff",
        "fg": "#000000",
        "text": "#000000",
        "accent": "#006699",
        "entry_bg": "#ffffff",
        "box_bg": "#f0f0f0",
        "warning": "#ff3b3f",
        "ok": "#007f5f"
    },
    "brown": {
        "bg": "#4b3832",
        "fg": "#ffffff",
        "text": "#ffffff",
        "accent": "#a1866f",
        "entry_bg": "#3b2f2f",
        "box_bg": "#3b2f2f",
        "warning": "#ff6666",
        "ok": "#cddc39"
    },
    "beige": {
        "bg": "#f5f5dc",
        "fg": "#4b3832",
        "text": "#4b3832",
        "accent": "#a1866f",
        "entry_bg": "#fdf6e3",
        "box_bg": "#f0e8d9",
        "warning": "#d64541",
        "ok": "#4caf50"
    },
    "dark": {
        "bg": "#121212",
        "fg": "#e0e0e0",
        "text": "#d3d3d3",
        "accent": "#03dac6",
        "entry_bg": "#1e1e1e",
        "box_bg": "#1e1e1e",
        "warning": "#ff5370",
        "ok": "#a3e635"
    }
}

theme_names = list(theme.keys())
current_theme_index = 0
current_theme = theme[theme_names[current_theme_index]]


# ========== TKINTER WINDOW ==========
root = tk.Tk()
root.title("🐙 Locktopus - Password Assistant")
root.geometry("980x750")

style = ttk.Style()
style.theme_use("clam")

password_var = tk.StringVar()

# ========== FUNCTIONS ==========
def apply_theme():
    th = current_theme
    root.configure(bg=th["bg"])
    style.configure("TButton", background=th["accent"], foreground=th["fg"])

    title_label.configure(bg=th["bg"], fg=th["accent"])
    entry.configure(bg=th["entry_bg"], fg=th["fg"], insertbackground=th["fg"])
    output.configure(bg=th["box_bg"], fg=th["fg"])
    hash_output.configure(bg=th["box_bg"], fg=th["fg"])
    entropy_label.configure(bg=th["bg"], fg=th["fg"])
    strength_result.configure(bg=th["bg"], fg=th["fg"])
    breach_label.configure(bg=th["bg"], fg=th["fg"])
    breach_label.config(text="Click 'Check Breach' to verify password against known breaches.")
    show_pass_btn.configure(bg=th["bg"], fg=th["fg"], selectcolor=th["bg"], activebackground=th["bg"])
    hash_label.configure(bg=th["bg"], fg=th["accent"])
    algo_listbox.configure(bg=th["box_bg"], fg=th["fg"], selectbackground=th["accent"])
    toggle_btn.configure(bg=th["bg"], fg=th["accent"], activebackground=th["bg"])

    for lbl in rule_labels:
        lbl.configure(bg=th["bg"], fg=th["fg"])

def toggle_theme():
    global current_theme_index, current_theme
    current_theme_index = (current_theme_index + 1) % len(theme_names)
    current_theme = theme[theme_names[current_theme_index]]
    apply_theme()


def check_rules(password):
    return {
        "Length": len(password) >= config["min_length"],
        "Uppercase": not config["require_upper"] or any(c.isupper() for c in password),
        "Lowercase": not config["require_lower"] or any(c.islower() for c in password),
        "Digit": not config["require_digit"] or any(c.isdigit() for c in password),
        "Symbol": not config["require_symbol"] or any(c in string.punctuation for c in password)
    }

def calculate_entropy(password):
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c in string.punctuation for c in password): pool += len(string.punctuation)
    return round(len(password) * math.log2(pool), 2) if pool else 0

def estimate_crack_time(entropy):
    guesses = 2 ** entropy
    seconds = guesses / config["guesses_per_second"]
    if seconds < 60: return f"{seconds:.2f}s"
    elif seconds < 3600: return f"{seconds/60:.2f} min"
    elif seconds < 86400: return f"{seconds/3600:.2f} hrs"
    elif seconds < 31536000: return f"{seconds/86400:.2f} days"
    return f"{seconds/31536000:.2f} years"

def detect_patterns(password):
    pw = password.lower()
    patterns = []

    # 1. Repeated characters (aaa, bbbb)
    if re.search(r'(.)\1{' + str(config["max_repeating_chars"]) + ',}', pw):
        patterns.append("🔁 Repeated characters")

    # 2. Repeating chunk patterns like ababab or xyzxyz
    for size in range(2, len(pw) // 2 + 1):
        chunk = pw[:size]
        if chunk * (len(pw) // size) == pw:
            patterns.append(f"🧩 Repeating chunk pattern: '{chunk}'")
            break

    # 3. Common keyboard sequences
    if re.search(r'(123|1234|abcd|qwer|asdf|zxcv)', pw):
        patterns.append("🔡 Common keyboard pattern")

    return patterns


def detect_dictionary_words(password):
    return sorted({word for word in DICTIONARY if word in password.lower()})

def detect_context(password):
    pw = password.lower()
    return [w for w in config["disallowed_words"] if w in pw]

def apply_regex_checks(password):
    issues = []
    if config["must_match_regex"] and not re.search(config["must_match_regex"], password):
        issues.append("⚠️ Missing required pattern")
    if config["must_not_match_regex"] and re.search(config["must_not_match_regex"], password):
        issues.append("🚫 Matches forbidden pattern")
    return issues

def check_pwned_sha1(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        res = requests.get(url, timeout=3)
        for line in res.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return f"🛑 Found in {count} breaches!"
        return "✅ Not found in known breaches."
    except:
        return "⚠️ Could not check breaches (offline?)"

def get_all_hashes(password):
    return {
        "SHA1": hashlib.sha1(password.encode()).hexdigest().upper(),
        "MD5": hashlib.md5(password.encode()).hexdigest().upper(),
        "SHA-256": hashlib.sha256(password.encode()).hexdigest().upper(),
        "SHA-512": hashlib.sha512(password.encode()).hexdigest().upper()
    }

def score_password(password, rules, entropy, issues):
    score = sum(rules.values())
    score += 2 if entropy > 80 else 1 if entropy > 60 else 0
    score -= len(issues)
    return max(0, min(score, 10))

def strength_label(score):
    if score <= 2: return "💀 Very Weak", "red"
    elif score <= 4: return "❌ Weak", "orangered"
    elif score <= 6: return "⚠️ Okay", "orange"
    elif score <= 8: return "✅ Strong", "lime"
    return "💪 Elite", "cyan"

def update_feedback(*args):
    pw = password_var.get()
    rules = check_rules(pw)
    entropy = calculate_entropy(pw)
    crack_time = estimate_crack_time(entropy)
    dict_words = detect_dictionary_words(pw)
    patterns = detect_patterns(pw)
    context_hits = detect_context(pw)
    regex_issues = apply_regex_checks(pw)
    # issues = dict_words + patterns + context_hits + regex_issues
    advanced_patterns = detect_advanced_patterns(pw)
    issues = dict_words + patterns + advanced_patterns + context_hits + regex_issues

    score = score_password(pw, rules, entropy, issues)
    strength, color = strength_label(score)
    for i, (r, ok) in enumerate(rules.items()):
        rule_labels[i].config(text=f"{'✅' if ok else '❌'} {r}")
    output.config(state="normal")
    output.delete("1.0", tk.END)
    output.insert(tk.END, "\n".join(issues) if issues else "✅ No major issues")
    output.config(state="disabled")
    entropy_label.config(text=f"Entropy: {entropy:.2f} bits | Crack Time: {crack_time}")
    strength_bar["value"] = score * 10
    strength_result.config(text=strength, fg=color)

def check_breach():
    pw = password_var.get()
    if not pw:
        messagebox.showwarning("No Password", "Enter a password first.")
        return
    breach_label.config(text="⏳ Checking...")
    result = check_pwned_sha1(pw)
    breach_label.config(text=result, fg="red" if "🛑" in result else "lime")

def generate_hashes():
    pw = password_var.get()
    if not pw:
        messagebox.showwarning("No Password", "Enter a password first.")
        return
    selected = [algo_listbox.get(i) for i in algo_listbox.curselection()]
    hashes = get_all_hashes(pw)
    output_lines = [f"{algo}: {hashes[algo]}" for algo in selected]
    hash_output.config(state="normal")
    hash_output.delete("1.0", tk.END)
    hash_output.insert(tk.END, "\n".join(output_lines))
    hash_output.config(state="disabled")

# ========== UI ==========
title_label = tk.Label(root, text="🐙 Locktopus - Ultimate Password Assistant", font=("Segoe UI", 16, "bold"))
title_label.pack(pady=(10, 0))

toggle_btn = tk.Button(root, text="🌗 Toggle Light/Dark Mode", command=toggle_theme)
toggle_btn.pack(pady=(5, 5))

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both')

frame1 = tk.Frame(notebook)
frame2 = tk.Frame(notebook)
notebook.add(frame1, text='Password Checker')
notebook.add(frame2, text='Hash Tools')

# ===== Frame 1: Password Checker =====
entry = tk.Entry(frame1, textvariable=password_var, font=("Segoe UI", 14), width=35, show="*")
entry.pack(pady=5)

show_var = tk.BooleanVar()
show_pass_btn = tk.Checkbutton(frame1, text="Show Password", variable=show_var,
               command=lambda: entry.config(show="" if show_var.get() else "*"))
show_pass_btn.pack()

rule_frame = tk.Frame(frame1)
rule_frame.pack(pady=10)
rule_labels = []
for rule in ["Length", "Uppercase", "Lowercase", "Digit", "Symbol"]:
    lbl = tk.Label(rule_frame, text=f"❌ {rule}", anchor="w", width=40)
    lbl.pack()
    rule_labels.append(lbl)

output = tk.Text(frame1, height=5, width=70, state="disabled", font=("Courier", 10))
output.pack(pady=5)

entropy_label = tk.Label(frame1, text="Entropy: 0 bits | Crack Time: 0s", font=("Segoe UI", 10))
entropy_label.pack()

strength_bar = ttk.Progressbar(frame1, length=400, maximum=100, mode='determinate')
strength_bar.pack(pady=5)

strength_result = tk.Label(frame1, text="Score", font=("Segoe UI", 12, "bold"))
strength_result.pack()

ttk.Button(frame1, text="🔍 Check Breach (SHA1)", command=lambda: Thread(target=check_breach).start()).pack(pady=5)

breach_label = tk.Label(frame1, text="", font=("Segoe UI", 10))
breach_label.pack()

# ===== Frame 2: Hash Generator =====
hash_label = tk.Label(frame2, text="🔐 Hash Generator", font=("Segoe UI", 12, "bold"))
hash_label.pack(pady=10)

algo_listbox = tk.Listbox(frame2, selectmode="multiple", height=4, exportselection=False)
for algo in ["SHA1", "MD5", "SHA-256", "SHA-512"]:
    algo_listbox.insert(tk.END, algo)
algo_listbox.selection_set(0)
algo_listbox.pack()

hash_output = tk.Text(frame2, height=8, width=80, state="disabled", font=("Courier", 10))
hash_output.pack(pady=5)

ttk.Button(frame2, text="🧮 Generate Hashes", command=generate_hashes).pack(pady=5)

# ========= INIT =========
password_var.trace_add("write", update_feedback)
apply_theme()
root.mainloop()
