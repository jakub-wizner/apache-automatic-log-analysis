import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

class MailSender:
  def send_email(receiver_email, subject, body, sender_email="ioprog2025@gmail.com", 
               password="oajijcunkmnbzsef", html_path=None):
      port = 465
      smtp_server = "smtp.gmail.com"
    
      message = MIMEMultipart()
      message["From"] = sender_email
      message["To"] = receiver_email
      message["Subject"] = subject
    
      message.attach(MIMEText(body, "plain"))
    
      if html_path:
          try:
              html_file = Path(html_path)
            
              if not html_file.exists():
                  print(f"Error: File not found: {html_path}")
                  return False
            
              if html_file.suffix.lower() not in ['.html', '.htm']:
                  print(f"Warning: File doesn't have .html/.htm extension: {html_path}")
            
              with open(html_file, "rb") as f:
                  html_attachment = MIMEBase("text", "html")
                  html_attachment.set_payload(f.read())
                  encoders.encode_base64(html_attachment)
                  html_attachment.add_header(
                      "Content-Disposition",
                      f"attachment; filename={html_file.name}"
                  )
                  message.attach(html_attachment)
                
          except Exception as e:
              print(f"Error attaching HTML file: {e}")
              return False
    
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

