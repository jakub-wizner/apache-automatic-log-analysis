import smtplib
import ssl

def send_email(receiver_email, subject, body, sender_email="ioprog2025@gmail.com",  password="oajijcunkmnbzsef"):
    port = 465 #SSL
    smtp_server = "smtp.gmail.com"
    
    message = f"""\
Subject: {subject}

{body}"""
    
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
        print("Email sent successfully")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

#Przykładowe wywołanie
#send_email(
#    receiver_email="test@gmail.com",
#    subject="Test",
#    body="To jest test"
#)