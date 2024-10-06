import tkinter as tk
from tkinter import ttk
import hashlib
import re

try:
    import requests #Need to pip install requests
except ModuleNotFoundError:
    print("Need to pip install requests")
    quit()

class PasswordStrengthChecker:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Strength Checker")
        self.master.geometry("600x500")
        self.create_widgets()

    def create_widgets(self):
        password_label = tk.Label(self.master, text="Enter password:",font=('Arial',16))
        password_label.pack(pady=(30, 10))

        self.password_entry = tk.Entry(self.master, show="*", width=30,font=('Arial',14))
        self.password_entry.pack(pady=(5, 5))

        self.show_password_var = tk.BooleanVar()
        show_password_checkbox = tk.Checkbutton(self.master, text="Show password", 
                                                variable=self.show_password_var, 
                                                command=self.toggle_password_visibility)
        show_password_checkbox.pack()

        check_button = tk.Button(self.master, text="Check Strength",font=('Arial',14), command=self.check_password)
        check_button.pack(pady=10)

        self.result_label = tk.Label(self.master, text="")
        self.result_label.pack()

        self.strength_bar = ttk.Progressbar(self.master, length=200, mode='determinate')
        self.strength_bar.pack(pady=10)

        self.feedback_text = tk.Text(self.master, height=6, width=40, wrap=tk.WORD)
        self.feedback_text.pack(pady=10)

        # Button to open the second window
        open_second_window_button = tk.Button(self.master, text="Have I Been Pwned?",font=('Arial',14), bg="red", fg='white', 
                                              command=self.open_second_window)
        open_second_window_button.pack(pady=10)

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def check_password(self):
        password = self.password_entry.get()
        
        if not password:
            self.result_label.config(text="Please enter a password.", fg="red",font=('Arial',14))
            self.strength_bar['value'] = 0
            return

        score, feedback = self.password_strength(password)
        
        if score <= 2:
            color = "red"
            strength = "Weak"
        elif score <= 3:
            color = "orange"
            strength = "Moderate"
        else:
            color = "green"
            strength = "Strong"
        
        self.result_label.config(text=f"Password strength: {strength}", fg=color,font=('Arial',14))
        self.strength_bar['value'] = score * 20  # 5 levels, each 20%
        
        self.feedback_text.delete('1.0', tk.END)
        if feedback:
            self.feedback_text.insert(tk.END, "Suggestions to improve:\n")
            for suggestion in feedback:
                self.feedback_text.insert(tk.END, f"• {suggestion}\n")

    def password_strength(self, password):
        score = 0
        feedback = []

        if len(password) < 8:
            feedback.append("Password is too short. It should be at least 8 characters.")
        else:
            score += 1

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters.")

        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters.")

        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Add numbers.")

        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            feedback.append("Add special characters.")

        return score, feedback

    def open_second_window(self):
        SecondWindow(self.master)

class SecondWindow:
    def __init__(self, master):
        self.top = tk.Toplevel(master)
        self.top.title("Have I Been Pwned?")
        self.top.geometry("600x500")
        self.top.configure(bg='#636B71')

        self.frame = tk.Frame(self.top, bg='#636B71')
        self.frame.pack(expand=True, fill='both')

        self.output = tk.Label(self.frame)
        self.pwned_output = tk.Label(self.frame)

        self.create_widgets()

    def create_widgets(self):
        # Title Label
        title_label = tk.Label(self.frame, text="Have I Been Pwned?", fg="#B6E3E4", bg="#636B71", font=('Arial', 30))
        title_label.pack(pady=10)
        # Password Entry
        password_label = tk.Label(self.frame, text="Password: ", fg="#B6E3E4", bg="#636B71", font=('Arial', 14))
        password_label.pack(pady=10)
        self.password_entry = tk.Entry(self.frame, show="*", font=('Arial', 14), width=30)
        self.password_entry.pack(pady=10)
        self.password_entry.focus_set()

        # Show Password Checkbox
        self.show_password_var = tk.IntVar()
        show_pass = tk.Checkbutton(self.frame, text='Show Password?', font=('Arial', 12), 
                                   selectcolor="white", fg="#B6E3E4", bg="#636B71", 
                                   activeforeground="#636B71", variable=self.show_password_var, 
                                   onvalue=1, offvalue=0, command=self.show_password)
        show_pass.pack(pady=10)

        # Check Button
        check_button = tk.Button(self.frame, text="Check Password", fg="black", bg="#BFC0BD", 
                                 activebackground="#75878A", activeforeground="white", 
                                 font=('Arial', 14), command=self.check_pass)
        check_button.pack(pady=10)

    def show_password(self):
        if self.show_password_var.get() == 1:
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def check_pass(self):
        self.output.destroy()
        self.pwned_output.destroy()
        pswd = self.password_entry.get()
        response = self.check_pwned_status(pswd)

        if not pswd:
            self.pwned_output = tk.Label(self.frame, text="Please input a password", 
                                         fg="#FF7570", bg="#636B71", font=('Arial', 16))
            self.output = tk.Label(self.frame, text="No password input",
                                   fg="#FF7570", bg="#636B71", wraplength=400, font=('Arial', 14))
        elif response == "This password isn't in the list":
            self.pwned_output = tk.Label(self.frame, text="Good news! - No pwnage found.", 
                                         fg="#03EE41", bg="#636B71", font=('Arial', 16))
            self.output = tk.Label(self.frame, text="This password wasn't found in any of the sources loaded into Have I been pwned.",
                                   fg="#03EE41", bg="#636B71", wraplength=400, font=('Arial', 14))
        else:
            self.pwned_output = tk.Label(self.frame, text="Your Password has been Pwned!", 
                                         fg="#FF7570", bg="#636B71", font=('Arial', 16))
            self.output = tk.Label(self.frame, text=f"This password has previously appeared in a data breach and should never be used. There are {response} instances of this password in the Have I been pwned database.",
                                   fg="#FF7570", bg="#636B71", wraplength=400, font=('Arial', 14))

        self.pwned_output.pack(pady=10)
        self.output.pack(pady=10)

    def check_pwned_status(self, password_input):
        pattern = re.compile(r'[:\s]\s*')
        password = password_input
        website = "https://api.pwnedpasswords.com/range/"

        final_Hash_hex = hashlib.sha1(password.encode()).hexdigest()
        hash_prefix = final_Hash_hex[:5]

        r = requests.get(website + hash_prefix, headers={"Add-Padding": "true"})
        api_hash_output = r.text
        split_list = re.split(pattern, api_hash_output)
        pass_hash_suffix = final_Hash_hex[5:].upper()

        try:
            index = split_list.index(pass_hash_suffix)
            return split_list[index + 1]
        except ValueError:
            return "This password isn't in the list"
   
            
        
def main():
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()

if __name__ == "__main__":
    main()