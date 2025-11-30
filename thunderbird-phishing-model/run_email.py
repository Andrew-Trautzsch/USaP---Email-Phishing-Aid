import json
from score_email import score_email

# Load the email JSON from the file in this folder
with open("tmp.json", "r", encoding="utf-8") as f:
    email_data = json.load(f)

# Run the phishing-risk model
result = score_email(email_data)

print(json.dumps(result, indent=2))
