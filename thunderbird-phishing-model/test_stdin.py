import json
from score_email import score_email

email = {
    "plainText": "Hello, verify your account now.",
    "headers": {"authentication-results": ["spf=fail"]},
    "links": [{"href": "http://bit.ly/fake-link"}]
}

result = score_email(email)
print(json.dumps(result, indent=2))
