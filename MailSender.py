import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

def send_email(receiver_email, subject, body, sender_email="ioprog2025@gmail.com", 
               password="oajijcunkmnbzsef", attachments=None):
    port = 465
    smtp_server = "smtp.gmail.com"
    
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject
    
    message.attach(MIMEText(body, "plain"))
    
    if attachments:
        if isinstance(attachments, str):
            attachments = [attachments]
        
        for file_path in attachments:
            try:
                file = Path(file_path)
                
                if not file.exists():
                    print(f"Error: File not found: {file_path}")
                    continue
                
                with open(file, "rb") as f:
                    if file.suffix.lower() in ['.html', '.htm']:
                        attachment = MIMEBase("text", "html")
                    elif file.suffix.lower() == '.pdf':
                        attachment = MIMEBase("application", "pdf")
                    elif file.suffix.lower() in ['.jpg', '.jpeg', '.png', '.gif']:
                        attachment = MIMEBase("image", file.suffix[1:])
                    else:
                        attachment = MIMEBase("application", "octet-stream")
                    
                    attachment.set_payload(f.read())
                    encoders.encode_base64(attachment)
                    attachment.add_header(
                        "Content-Disposition",
                        f"attachment; filename={file.name}"
                    )
                    message.attach(attachment)
                    
            except Exception as e:
                print(f"Error attaching file {file_path}: {e}")
                continue
    
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
#Wywołanie:

#send_email(
#    receiver_email="test@gmail.com",
#    subject="Test",
#    body="To jest test"
#)
    
#send_email(
#    receiver_email="test@gmail.com",
#    subject="Test z załącznikiem HTML",
#    body="To jest test z załącznikiem HTML",
#    html_path="index.html"
#)



