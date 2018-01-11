import csv
import json
import os
import smtplib
from smtplib import SMTPRecipientsRefused, SMTPHeloError, SMTPSenderRefused, SMTPDataError, SMTPServerDisconnected
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import pendulum
from UserStatisticsCollector import UserStatisticsCollector

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'
from crits.core.user_tools import get_user_email_notification, get_email_address


class UserStatisticsReporter:

    def __init__(self):
        self.collector = UserStatisticsCollector()
        configs_directory = "/data/configs/"
        self.reports_directory = "/data/reports/"
        reporting_config_filename = configs_directory + "reporting_config.json"
        self.user_statistics_message_filename = configs_directory + 'user_statistics_message.txt'
        self.report_file_message_filename = configs_directory + 'report_file_message.txt'
        with open(reporting_config_filename, 'r') as reporting_config_file:
            configs = json.load(reporting_config_file)
            self.sender_email = str(configs['sender_email'])
            self.report_file_recipients = configs['recipients']
            self.password = str(configs['password'])

    def run(self):
        # Store today's date to make sure all calculations are done relative to this date.
        today_utc = pendulum.today('UTC')
        yesterday_start = today_utc.subtract(days=1)
        yesterday_end = today_utc.subtract(microseconds=1)
        report_date_string = yesterday_start.to_date_string()
        user_statistics_file_path = self.reports_directory+'user_statistics_for_'+report_date_string+'.csv'
        self.write_statistics(user_statistics_file_path, yesterday_start, yesterday_end)
        self.email_statistics(user_statistics_file_path, yesterday_start)

    def write_statistics(self, report_filepath, duration_start, duration_end):
        field_names = ['Username', 'First Name', 'Last Name', 'Company', 'Email', 'IPs', 'Events']
        with open(report_filepath, 'wb') as csv_file:
            stats_writer = csv.DictWriter(csv_file, fieldnames=field_names)
            stats_writer.writeheader()
            for user in self.collector.find_users():
                username = user['username']
                submissions_counts = self.collector.count_submissions_from_user_within_duration(username, duration_start, duration_end)
                next_row = {
                    'Username': username,
                    'First Name': user['first_name'],
                    'Last Name': user['last_name'],
                    'Company': user['organization'],
                    'Email': user['email'],
                    'IPs': submissions_counts['ips'],
                    'Events': submissions_counts['events']
                }
                stats_writer.writerow(next_row)

    def email_statistics(self, report_filepath, report_date):
        server = smtplib.SMTP(host='smtp.office365.com', port=587)
        server.ehlo()
        server.starttls()
        server.login(self.sender_email, self.password)
        for recipient in self.report_file_recipients:
            report_message = MIMEMultipart()
            with open(self.report_file_message_filename, 'r') as report_file_message:
                body_text = report_file_message.read()
            body_text = body_text.format(date=report_date.to_formatted_date_string()) + "\n"
            with open(report_filepath, 'r') as user_stats_file:
                stats_reader = csv.DictReader(user_stats_file)
                for row in stats_reader:
                    username = row['Username']
                    company = row['Company']
                    ips = row['IPs']
                    events = row['Events']
                    lines = [
                        'Username: ' + username,
                        'Company: ' + company,
                        'IPs: ' + ips,
                        'Events: ' + events
                    ]
                    for line in lines:
                        body_text += line + "\n"
                    body_text += "\n"
            body = MIMEMultipart('alternative')
            body.attach(MIMEText(body_text))
            report_message.attach(body)
            report_message['From'] = self.sender_email
            report_message['To'] = recipient
            report_message['Date'] = formatdate(localtime=True)
            report_message['Subject'] = "User Submissions Report: " + report_date.to_formatted_date_string()
            try:
                server.sendmail(self.sender_email, recipient, report_message.as_string())
            except (SMTPRecipientsRefused, SMTPHeloError, SMTPSenderRefused,
                    SMTPDataError, SMTPServerDisconnected) as e:
                print "Error:", e

        with open(report_filepath, 'r') as user_stats_file:
            stats_reader = csv.DictReader(user_stats_file)
            for row in stats_reader:
                username = row['Username']
                if not get_user_email_notification(username):
                    # Don't send mail if user has disabled email notifications.
                    continue
                number_of_ips = row['IPs']
                number_of_events = row['Events']
                with open(self.user_statistics_message_filename, 'r') as message_file:
                    message = MIMEText(message_file.read())
                message['From'] = self.sender_email
                to_email = get_email_address(username)
                message['To'] = to_email
                message['Date'] = formatdate(localtime=True)
                if number_of_ips == '0' and number_of_events == '0':
                    message['Subject'] = "Alert: No Data Received for User '" + username + "'"
                else:
                    message['Subject'] = "Statistics for User '" + username + "'"
                message_string = message.as_string()
                message_string = message_string.format(username=username,
                                                       number_of_ips=number_of_ips,
                                                       number_of_events=number_of_events)
                try:
                    server.sendmail(self.sender_email, to_email, message_string)
                except (SMTPRecipientsRefused, SMTPHeloError, SMTPSenderRefused,
                        SMTPDataError, SMTPServerDisconnected) as e:
                    print "Error:", e
        server.quit()
