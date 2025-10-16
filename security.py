from tkinter import simpledialog, messagebox
import random
import string
import threading

from notifier import send_password_email

def generate_otp(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def authenticate_action(action_name, intended_email, log_function):
    otp = generate_otp()
    
    threading.Thread(
        target=send_password_email, 
        args=(intended_email, action_name, otp), 
        daemon=True
    ).start()
    
    messagebox.showinfo(
        "Password Required", 
        f"A One-Time Password (OTP) has been sent to {intended_email}.\nPlease check your inbox and enter the OTP below."
    )

    user_input = simpledialog.askstring(
        "Authentication", 
        f"Enter the OTP sent to {intended_email} to proceed with '{action_name}':"
    )

    if user_input and user_input.strip() == otp:
        log_function(f"Authentication Successful for {action_name}") 
        return True
    else:
        messagebox.showerror("Authentication Failed", "Invalid or missing One-Time Password.")
        log_function(f"Authentication Failed for {action_name}") 
        return False