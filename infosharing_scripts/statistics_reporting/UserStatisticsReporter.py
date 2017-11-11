import csv
import json
import os
import smtplib
from smtplib import SMTPRecipientsRefused, SMTPHeloError, SMTPSenderRefused, SMTPDataError, SMTPServerDisconnected
from email.mime.text import MIMEText
from email.utils import formatdate
import pendulum

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'
from crits.core.user_tools import get_user_email_notification, get_email_address

from UserStatisticsCollector import UserStatisticsCollector


class UserStatisticsReporter:

    def __init__(self):
        self.collector = UserStatisticsCollector()
        self.reports_directory = "/data/reports"
        reporting_config_filename = self.reports_directory + "/reporting_config.json"
        self.user_statistics_message_filename = self.reports_directory + '/user_statistics_message.txt'
        with open(reporting_config_filename, 'r') as reporting_config_file:
            configs = json.load(reporting_config_file)
            self.sender_email = configs['sender_email']

    def run(self):
        # Store today's date to make sure all calculations are done relative to this date.
        today = pendulum.today('UTC')
        yesterday_start = today.subtract(days=1)
        yesterday_end = today.subtract(microseconds=1)
        report_date = yesterday_start.to_date_string()
        user_statistics_file_path = self.reports_directory+'/user_statistics_for_'+report_date+'.csv'
        self.write_statistics(user_statistics_file_path, yesterday_start, yesterday_end)
        self.email_statistics(user_statistics_file_path)

    def write_statistics(self, report_filepath, duration_start, duration_end):
        field_names = ['Username', 'IPs', 'Events']
        with open(report_filepath, 'wb') as csv_file:
            stats_writer = csv.DictWriter(csv_file, fieldnames=field_names)
            stats_writer.writeheader()
            for user in self.collector.find_users():
                username = user['username']
                submissions_counts = self.collector.count_submissions_from_user_within_duration(username, duration_start, duration_end)
                next_row = {
                    'Username': username,
                    'IPs': submissions_counts['ips'],
                    'Events': submissions_counts['events']
                }
                stats_writer.writerow(next_row)
                print "Wrote number of submissions for user '" + username + "'."

    def email_statistics(self, report_filepath):
        server = smtplib.SMTP(host='mailhost.cablelabs.com')
        server.starttls()
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
                # TODO: When done testing code, set recepient to the user whose stats we're reporting.
                # to_email = get_email_address(username)
                # message['To'] = to_email
                message['To'] = 'z.hintzman@cablelabs.com'
                message['Date'] = formatdate(localtime=True)
                message['Subject'] = "Statistics for User '" + username + "'"
                message_string = message.as_string()
                message_string = message_string.format(username=username,
                                                       number_of_ips=number_of_ips,
                                                       number_of_events=number_of_events)
                try:
                    #server.sendmail(from_email, to_email, message_string)
                    server.sendmail(self.sender_email, 'z.hintzman@cablelabs.com', message_string)
                except (SMTPRecipientsRefused, SMTPHeloError, SMTPSenderRefused,
                        SMTPDataError, SMTPServerDisconnected) as e:
                    print e
        server.quit()
