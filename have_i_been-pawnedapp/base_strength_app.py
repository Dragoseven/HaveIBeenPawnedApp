import tkinter as tk
from tkinter import ttk
import re

def password_strength(password):
    score = 0
    feedback = []

    # Check length
    if len(password) < 8:
        feedback.append("Password is too short. It should be at least 8 characters.")
    else:
        score += 1

    # Check for uppercase letters
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    # Check for lowercase letters
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    # Check for numbers
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    # Check for special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add special characters.")

    return score, feedback

def check_password():
    password = password_entry.get()
    
    if not password:
        result_label.config(text="Please enter a password.", fg="red")
        strength_bar['value'] = 0
        return

    score, feedback = password_strength(password)
    
    if score <= 2:
        color = "red"
        strength = "Weak"
    elif score <= 3:
        color = "orange"
        strength = "Moderate"
    else:
        color = "green"
        strength = "Strong"
    
    result_label.config(text=f"Password strength: {strength}", fg=color)
    strength_bar['value'] = score * 20  # 5 levels, each 20%
    
    feedback_text.delete('1.0', tk.END)
    if feedback:
        feedback_text.insert(tk.END, "Suggestions to improve:\n")
        for suggestion in feedback:
            feedback_text.insert(tk.END, f"• {suggestion}\n")

def toggle_password_visibility():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

# Create the main window
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x350")

# Create and place the widgets
password_label = tk.Label(root, text="Enter password:")
password_label.pack(pady=(20, 0))

password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=(5, 5))

# Add show password checkbox
show_password_var = tk.BooleanVar()
show_password_checkbox = tk.Checkbutton(root, text="Show password", variable=show_password_var, command=toggle_password_visibility)
show_password_checkbox.pack()

check_button = tk.Button(root, text="Check Strength", command=check_password)
check_button.pack(pady=10)

result_label = tk.Label(root, text="")
result_label.pack()

strength_bar = ttk.Progressbar(root, length=200, mode='determinate')
strength_bar.pack(pady=10)

feedback_text = tk.Text(root, height=5, width=40, wrap=tk.WORD)
feedback_text.pack(pady=10)

# Start the GUI event loop
root.mainloop()