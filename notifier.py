import time
import smtplib
from email.message import EmailMessage
import ssl
import threading

SMTP_SERVER = 'smtp.gmail.com' 
SMTP_PORT = 587
SENDER_EMAIL = 'abcd@gmail.com' # Replace with your actual sender email
EMAIL_PASSWORD = 'abcdefghijklmnop' # Replace with your actual app password

email_lock = threading.Lock() 

def _send_email_task(to_email, subject, body):
    with email_lock:
        try:
            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = SENDER_EMAIL
            msg['To'] = to_email
            msg.set_content(body) 

            context = ssl.create_default_context()

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls(context=context)
                server.login(SENDER_EMAIL, EMAIL_PASSWORD)
                server.send_message(msg)
            print(f"Successfully sent email to {to_email} for: {subject}")
        except Exception as e:
            print(f"Error sending email: {e}")


def send_email(to_email, subject, body):
    threading.Thread(
        target=_send_email_task, 
        args=(to_email, subject, body),
        daemon=True
    ).start()


def send_attack_alert(recipient_email, attack_type, src_ip, dst_ip):
    if not recipient_email or recipient_email == "N/A":
        print("ALERT: Attack detected, but no alert email is configured.")
        return
    subject = f"🚨 SECURITY ALERT: {attack_type} Detected!"
    body = f"""
A potential network attack was detected by the sniffer.

Attack Type: {attack_type}
Source IP: {src_ip}
Target IP: {dst_ip}
Time: {time.strftime('%Y-%m-%d %H:%M:%S')}

Action Recommended: Investigate the source IP immediately.
"""
    print(f"ATTACK DETECTED! Attempting to send alert to {recipient_email}...")

    send_email(recipient_email, subject, body)

def send_password_email(recipient_email, action, password):
    subject = f"One-Time Password for Packet Sniffer Access: {action}"
    body = (
        f"You requested access to the '{action}' feature of the Python Packet Sniffer.\n\n"
        f"Your One-Time Password (OTP) is:\n\n"
        f"*** {password} ***\n\n"
        f"This password is valid for a short time and will allow you to proceed with the action."
    )
    send_email(recipient_email, subject, body)