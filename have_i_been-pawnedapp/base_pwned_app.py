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
main_win.title("Have I Been Pwned?")
main_win.geometry("600x500")
main_win.configure(bg='#636B71')
frame = Frame(main_win)
frame.configure(bg='#636B71')

output = Label(main_win)
pwned_output = Label(main_win)





def check_pwned_status(password_input):
    '''
    [] meta character to indicate a list of delimiter characters.
    The [] matches any single character in brackets. For example, [-;,.\s] will match either
    hyphen, comma, semicolon, dot, and a space character.
    followed by any amount of extra whitespace (zero or more). i.e \s*
    '''
    pattern =re.compile(r'[:\s]\s*') #regular expression pattern used to split up results from website api request
    password = password_input
    website = "https://api.pwnedpasswords.com/range/" #Website to send api request

    '''
    Generate an SHA1 hash from the password entered in by user.
    ONLY the first 5 characters of this hash will be sent to website api
    so that password is non-discoverable
    '''
    
    final_Hash_hex = hashlib.sha1(password.encode()).hexdigest() #The hexadecimal SHA1 of inputed password
    hash_prefix = final_Hash_hex[:5]  #the first 5 characters of the password sha1 hash to be appended to api address
    
    r = requests.get(website + hash_prefix, headers={"Add-Padding": "true"}) #sending our hash key to website to get a list of ~500 hashes
    status = r.status_code #Do we have a valid response back from the website? 200 if we do.

    api_hash_output = r.text #list of sha1 hashes from the api response
    split_list = re.split(pattern, api_hash_output) #splitting hashes with number of occurrances 
    pass_hash_suffix = final_Hash_hex[5:].upper() #need to capitilise char to match website results
    
    try:
        index = split_list.index(pass_hash_suffix)
        return split_list[index+1]
    except ValueError:
        return "This password isn't in the list"
    
    
def check_pass():
    global output, pwned_output # we can only access the global variable but cannot modify it from inside the function. So global keyword used here
    output.destroy() #delete last output response
    pwned_output.destroy()
    pswd = password.get() #get value entered into input field
    response = check_pwned_status(pswd)
    
    #in case nothing is written in input field*
    if not pswd:
        pwned_output = Label(frame,text="Please input a password", fg ="#FF7570", bg="#636B71", font=('Arial',16))
        output = Label(frame,text="No password input",
                       fg ="#FF7570", bg="#636B71", wraplength=400, font=('Arial',14))                 
        pwned_output.grid(row=4, column=0, columnspan=2, pady=10)
        output.grid(row=5, column=0, columnspan=2, pady=0)
          
    #check pwned status
    elif response == "This password isn't in the list":
        pwned_output = Label(frame,text="Good news! - No pwnaged found.", fg ="#03EE41", bg="#636B71", font=('Arial',16))
        output = Label(frame,text="This password wasn't found in any of the sources loaded into Have I been pwned.",
                       fg ="#03EE41", bg="#636B71", wraplength=400, font=('Arial',14))                 
        pwned_output.grid(row=4, column=0, columnspan=2, pady=10)
        output.grid(row=5, column=0, columnspan=2, pady=0)
    else:
        pwned_output = Label(frame,text="Your Password has been Pwned!", fg ="#FF7570", bg="#636B71", font=('Arial',16))
        output = Label(frame,text="This password has previously appeared in a data breach and should never be used. There is "+response+" instances of this password in the Have I been pwned database.",
                       fg ="#FF7570", bg="#636B71", wraplength=400, font=('Arial',14))
        pwned_output.grid(row=4, column=0, columnspan=2, pady=10)
        output.grid(row=5, column=0, columnspan=2, pady=0)    


def show_password():
    if (var1.get() == 1):
        password.config(show="");
    else:
        password.config(show="*");


#Creating Widgets
title_label = Label(frame,text="Have I Been Pwned?", fg ="#B6E3E4", bg="#636B71", font=('Arial',30))
password_label = Label(frame,text="Password: ", fg ="#B6E3E4", bg="#636B71", font=('Arial',14))
password= Entry(frame,show="*", font=('Arial', 14),width=30)
password.focus_set() # No need to click on input field to enter password
var1 = IntVar()
show_pass = Checkbutton(frame, text='Show Password?', font=('Arial', 12), selectcolor="white", fg ="#B6E3E4", bg="#636B71",  activeforeground="#636B71",
                        variable=var1, onvalue=1, offvalue=0, command=show_password)
check_button = Button(frame, text="Check Password", fg="black", bg="#BFC0BD", activebackground="#75878A", activeforeground="white", font=('Arial', 14), command=check_pass)



#Placing widgets on screen and styling
title_label.grid(row=0, column=0, columnspan=2,  sticky="news", pady=40)
password_label.grid(row=1, column=0)
password.grid(row=1, column=1)
show_pass.grid(row=2, column=1, pady=10)
check_button.grid(row=3, column=0, columnspan=2, pady=20)

frame.pack()

main_win.mainloop()