import imaplib
from email.parser import BytesParser
from email.policy import default
import json
import base64
import time
import requests
import simple_colors

from flask import Flask, request, jsonify


# Connect to the email server
def connect_mail(login, password):
    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(login + '@gmail.com', password)
    mail.select('inbox')
    return mail


# Your VirusTotal API key
vt_api_key = "313dfd2f502ee4d65afd004b740cc0ecfb5e8436f38f3bbe54655b87e29be5d6"

headers = {
    "x-apikey": vt_api_key
}


def scan_with_virustotal_v3(file_data, filename):
    url = "https://www.virustotal.com/api/v3/files"
    files = {'file': (filename, file_data)}
    response = requests.post(url, headers=headers, files=files)
    result = response.json()

    # Check if the upload was successful
    if response.status_code == 200:
        # API v3 uses 'id' instead of 'resource'
        file_id = result['data']['id']
        print(f"File {filename} uploaded to VirusTotal, file ID: {file_id}")
        return file_id
    else:
        print(f"Failed to upload {filename} to VirusTotal.")
        return None


def get_virustotal_report_v3(file_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        report = response.json()
        return report
    else:
        print(f"Failed to get the report for file ID {file_id}")
        return None


def write_report_to_file(report, filename="report.json"):
    with open(filename, 'a') as report_file:  # 'a' mode to append to the file
        json.dump(report, report_file, indent=4)
        report_file.write(",\n\n")


def full_scan(login, password):
    # Search for all emails
    mail = connect_mail(login, password)
    type, data = mail.search(None, 'ALL')

    emails = []  # List to store email dictionaries

    for num in data[0].split():
        typ, data = mail.fetch(num, '(RFC822)')
        raw_email = data[0][1]
        parser = BytesParser(policy=default)
        parsed_email = parser.parsebytes(raw_email)

        # Initialize dictionary to hold email parts
        email_details = {
            'From': parsed_email['from'],
            'Subject': parsed_email['subject'],
            'Body': None,
            'Attachments': []
        }

        # Check if the email is multipart
        if parsed_email.is_multipart():
            for part in parsed_email.iter_parts():
                # Get the content type
                content_type = part.get_content_type()
                content_disposition = part.get_content_disposition()
                # If part is text (plain or HTML)
                if content_type in ('text/plain', 'text/html') and content_disposition != 'attachment':
                    email_details['Body'] = part.get_content()
                    # If part is an attachment
                elif content_disposition == 'attachment':
                    filename = part.get_filename()
                    payload = part.get_payload(decode=True)
                    encoded_payload = base64.b64encode(payload)  # Encode the attachment
                    attachment = {
                        'Filename': filename,
                        'Data': encoded_payload.decode()  # Convert bytes to string for JSON serialization
                    }
                    email_details['Attachments'].append(attachment)
                    # Scan the attachment with VirusTotal v3
                    file_id = scan_with_virustotal_v3(encoded_payload, filename)
                    # Wait a bit for the scan to complete. You might need to adjust this.
                    print("Waiting for VirusTotal to process the file...")
                    time.sleep(20)  # Wait for 15 seconds initially.
                    # Get the report for the uploaded file (you might need to poll for this)
                    report = get_virustotal_report_v3(file_id)
                    if report:
                        write_report_to_file(report)

        else:
            # Email is not multipart
            payload = parsed_email.get_payload(decode=True)
            email_details['Body'] = payload.decode()
        emails.append(email_details)

    mail.close()
    mail.logout()

    # Convert the list of email details to JSON
    json_data = json.dumps(emails, indent=4)

    # Write the JSON data to a file
    with open('emails.json', 'w') as jsonfile:
        jsonfile.write(json_data)

    print("Emails have been written to emails.json")
    print("The scan report have been written to report.json\n")

    report_file_path = 'report.json'
    with open(report_file_path, 'r') as report_file:
        content = report_file.read()
        content = content[:-3]
    with open(report_file_path, 'w') as report_file:
        report_file.write("[" + content + "]")
    malicious_detections = 0
    message=''
    try:
        with open(report_file_path, 'r') as report_file:
            reports = json.load(report_file)
            for report in reports:
                stats = report.get("data", {}).get("attributes", {}).get("stats", {})
                malicious_detections += stats.get("malicious", 0)
        if malicious_detections > 0:
            print(simple_colors.red(
                f"There were {malicious_detections} malicious detections found in the report.\nOpen report.json for more details."))
            message=message+"There were {malicious_detections} malicious detections found in the report.\nOpen report.json for more details."
        else:
            print(simple_colors.green("No malicious detections were found. You're Safe!"))
            message=message+"No malicious detections were found. You're Safe!"
    except FileNotFoundError:
        print(f"The file {report_file_path} does not exist.")
        message = message + "The file {report_file_path} does not exist."
    except json.JSONDecodeError:
        print(f"There was an error decoding the JSON data from {report_file_path}.")
        message = message + "There was an error decoding the JSON data from {report_file_path}."
    except AttributeError as e:
        print(f"An error occurred: {e}")
        message = message + "There was an error decoding the JSON data from {report_file_path}."
    return message


# creat flask app
app = Flask(__name__)


@app.route("/scan", methods=["POST"])
def post_scan():
    login = request.args.get('login')
    password = request.args.get('password')
    message= full_scan(login, password)
    return message

if __name__== "__main__" :
    app.run(debug=True)
