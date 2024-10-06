from tkinter import *
import hashlib
import re

try:
    import requests #Need to pip install requests
except ModuleNotFoundError:
    print("Need to pip install requests")
    quit()
    
#Create an instance of tkinter frame
main_win= Tk()
main_win.title("Is my Password Strong?")
main_win.geometry("600x500")
main_win.configure(bg='#254462')
frame = Frame(main_win)
frame.configure(bg='#254462')
output = Label(main_win)
pwned_output = Label(main_win)
suggestion = Label(main_win)    



def main():
    
    score, feedback = check_password_strength(password)
    strength = display_strength_bar(score)

    pwned_output = Label(frame,text=f"Password strength:{strength}", fg ="#BA7F45", bg="#254462", font=('Arial',16))
    output = Label(frame,text="Suggestions to improve:",fg ="#BA7F45", bg="#254462", wraplength=400, font=('Arial',14))                 
    pwned_output.grid(row=4, column=0, columnspan=3, pady=10)
    output.grid(row=5, column=0, columnspan=2, pady=0)
    
    if feedback:
        for suggestion in feedback:
            suggestion = Label(frame, text =f"\n{feedback}", fg ="#FF7570", bg="#254462",wraplength=400, font=('Arial',14))
            suggestion.grid(row=6,rowspan=2, column=0, columnspan=4, pady=0)

def check_password_strength(password):
    global output, pwned_output,suggestion
    output.destroy()
    pwned_output.destroy()
    suggestion.destroy()
    pswd = password.get()
    
    score = 0
    feedback = []

    # Check length
    if len(pswd) < 8:
        feedback.append("Password is too short. It should be at least 8 characters.")
    else:
        score += 1

    # Check for uppercase letters
    if re.search(r"[A-Z]", pswd):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    # Check for lowercase letters
    if re.search(r"[a-z]", pswd):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    # Check for numbers
    if re.search(r"\d", pswd):
        score += 1
    else:
        feedback.append("Add numbers.")

    # Check for special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", pswd):
        score += 1
    else:
        feedback.append("Add special characters.")

    return score, feedback

def display_strength_bar(score):
    
    if score <= 2:
        strength = "Weak"
    elif score <= 3:
        strength = "Moderate"
    elif score <= 4:
        strength = "Strong"        
    else:
        strength = "Super Strong"
    return strength


#Creating Widgets
title_label = Label(frame,text="Is my Password Strong?", fg ="#BA7F45", bg="#254462", font=('Arial',30))
password_label = Label(frame,text="Password: ", fg ="white", bg="#254462", font=('Arial',14))
password= Entry(frame,show="", font=('Arial', 14),width=30)
password.focus_set() # No need to click on input field to enter password
check_button = Button(frame, text="Check Password", fg="white", bg="#BA7F45", activebackground="#B34545", activeforeground="white", font=('Arial', 14), command=main)

#Placing widgets on screen and styling
title_label.grid(row=0, column=0, columnspan=2,  sticky="news", pady=40)
password_label.grid(row=1, column=0)
password.grid(row=1, column=1)
check_button.grid(row=3, column=0, columnspan=2, pady=20)



frame.pack()

main_win.mainloop()