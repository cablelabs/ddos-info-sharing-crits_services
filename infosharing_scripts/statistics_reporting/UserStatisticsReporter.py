import csv
from datetime import datetime
import json, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
#from crits.core.user_tools import get_user_email_notification

from UserStatisticsCollector import UserStatisticsCollector


class UserStatisticsReporter:

    def __init__(self):
        self.collector = UserStatisticsCollector()
        self.user_statistics_message_filename = 'user_statistics_message.txt'

    def run(self):
        # Each file is named using the timestamp of the time the file was created (approximately).
        full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        time_now_str = datetime.now().strftime(full_time_format)
        user_statistics_file_path = 'reports/user_statistics_'+time_now_str+'.csv'
        self.write_statistics(user_statistics_file_path)
        self.email_statistics(user_statistics_file_path)

    def write_statistics(self, file_path):
        full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        csv_file = open(file_path, 'wb')
        stats_writer = csv.writer(csv_file)
        stats_writer.writerow(['Username', 'Time Collected', 'IPs', 'Events'])
        try:
            for user in self.collector.find_users():
                username = user['username']
                submissions_counts = self.collector.count_submissions_from_user_within_day(username)
                time_collected = submissions_counts['time_collected'].strftime(full_time_format)
                stats_writer.writerow([username, time_collected, submissions_counts['ips'], submissions_counts['events']])
                print "Wrote number of submissions for user '" + username + "'."
        finally:
            csv_file.close()

    def email_statistics(self, file_path):
        # Note: '40.97.138.66' is the IP address for 'smtp-mail.outlook.com'.
        server = smtplib.SMTP(host='40.97.138.66', port=587)
        server.starttls()
        credentials_file = open('reporting_config.json', 'r')
        credentials = json.load(credentials_file)
        from_email = credentials['address']
        password = credentials['password']
        server.login(from_email, password)

        user_stats_file = open(file_path, 'r')
        stats_reader = csv.reader(user_stats_file)
        for row in stats_reader:
            username = row[0]
            if username == 'Username':# or not get_user_email_notification(username):
                # Ignore first line of CSV file, and send email only if user has email notifications enabled.
                continue
            time_collected = row[1]
            number_of_ips = row[2]
            number_of_events = row[3]
            message_file = open(self.user_statistics_message_filename, 'r')
            message = MIMEText(message_file.read())
            message_file.close()
            message['From'] = from_email
            # TODO: When done testing code, set recepient to the user whose stats we're reporting.
            # user = self.collector.find_one_user(username)
            # message['To'] = user['email']
            message['To'] = from_email
            message['Date'] = formatdate(localtime=True)
            message['Subject'] = "Statistics for User '" + username + "'"
            message_string = message.as_string()
            message_string = message_string.format(username=username,
                                                   timestamp=time_collected,
                                                   number_of_ips=number_of_ips,
                                                   number_of_events=number_of_events)

            try:
                #result = server.sendmail(from_email, to_email, message_string)
                result = server.sendmail(from_email, from_email, message_string)
            except Exception as e:
                print e
            server.close()

#reporter = UserStatisticsReporter()
#reporter.run()
