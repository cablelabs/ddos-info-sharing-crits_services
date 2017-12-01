import csv, os
from datetime import datetime
import json, smtplib
from smtplib import SMTPRecipientsRefused, SMTPHeloError, SMTPSenderRefused, SMTPDataError, SMTPServerDisconnected
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import pendulum
from GlobalStatisticsCollector import GlobalStatisticsCollector

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'
from crits.core.user_tools import get_user_email_notification


class GlobalStatisticsReporter:

    def __init__(self):
        self.collector = GlobalStatisticsCollector()
        #self.reports_directory = "/data/reports/"
        self.reports_directory = ""
        reporting_config_filename = self.reports_directory + "reporting_config.json"
        self.global_statistics_message_filename = self.reports_directory + 'global_statistics_message.txt'
        with open(reporting_config_filename, 'r') as reporting_config_file:
            configs = json.load(reporting_config_file)
            self.sender_email = str(configs['sender_email'])
            self.report_file_recipients = configs['recipients']
            self.password = str(configs['password'])

    def run(self):
        # Store today's date to make sure all calculations are done relative to this date.
        today_utc = pendulum.today('UTC')
        yesterday_utc_date_string = today_utc.subtract(days=1).to_date_string()
        global_statistics_file_path = self.reports_directory+'global_statistics_through_'+yesterday_utc_date_string+'.csv'
        yesterday_end_utc = today_utc.subtract(microseconds=1)
        self.write_statistics(global_statistics_file_path, yesterday_end_utc)
        self.email_statistics(global_statistics_file_path)

    def write_statistics(self, file_path, end_time):
        """
        Write relevant statistics to CSV file.
        :param file_path: The name of the CSV file to which data is written.
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :return:
        """
        csv_file = open(file_path, 'wb')
        stats_writer = csv.writer(csv_file)
        stats_writer.writerow(['Statistic', 'Value'])
        try:
            start_time = datetime.now()
            total_ips = self.collector.count_ips_up_to_time(end_time)
            duration = datetime.now() - start_time
            print "Time to Count IPs:", duration
            stats_writer.writerow(['Total # of IPs', total_ips])
            print "Wrote total number of IPs."

            start_time = datetime.now()
            total_events = self.collector.count_events_up_to_time(end_time)
            duration = datetime.now() - start_time
            print "Time to Count Events:", duration
            stats_writer.writerow(['Total # of Events', total_events])
            print "Wrote total number of Events."

            start_time = datetime.now()
            total_ips_multiple_reporters = self.collector.count_ips_multiple_reporters(end_time)
            duration = datetime.now() - start_time
            print "Time to Count IPs, non-spoofed:", duration
            stats_writer.writerow(['# of IPs reported by multiple data providers', total_ips_multiple_reporters])
            print "Wrote number of IPs reported by more than one data provider."

            start_time = datetime.now()
            total_events_multiple_reporters = self.collector.count_events_multiple_reporters(end_time)
            duration = datetime.now() - start_time
            print "Time to Count Events, non-spoofed:", duration
            stats_writer.writerow(['# of Events for IPs reported by multiple data providers', total_events_multiple_reporters])
            print "Wrote number of Events for IPs reported by more than one data provider."

            stats_writer.writerow([])
            stats_writer.writerow(['Top Attack Types'])
            stats_writer.writerow(['Attack Type', 'Number of Events'])
            start_time = datetime.now()
            top_attack_type_counts = self.collector.count_events_top_attack_types_multiple_reporters(end_time)
            for attack_type, count in top_attack_type_counts:
                stats_writer.writerow([attack_type, count])
            duration = datetime.now() - start_time
            print "Time to Count Attack Types:", duration
            print "Wrote top 10 attack types."

            stats_writer.writerow([])
            stats_writer.writerow(['Top Attacking Countries'])
            stats_writer.writerow(['Country', 'Number of Events'])
            start_time = datetime.now()
            top_attacking_country_counts = self.collector.count_events_top_attacking_countries_multiple_reporters(end_time)
            duration = datetime.now() - start_time
            print "Time to Count Countries:", duration
            for country, count in top_attacking_country_counts:
                stats_writer.writerow([country, count])
            print "Wrote top 10 attacking countries."
        finally:
            csv_file.close()

    def email_statistics(self, file_path):
        server = smtplib.SMTP(host='smtp.office365.com', port=587)
        server.ehlo()
        server.starttls()
        server.login(self.sender_email, self.password)
        for user in self.collector.find_users():
            username = user['username']
            if not get_user_email_notification(username):
                # Don't send mail if user has disabled email notifications.
                continue
            to_email = user['email']
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = to_email
            msg['Date'] = formatdate(localtime=True)
            msg['Subject'] = "Global Statistics"
            # TODO: Figure out what file format our team and participants want.
            global_stats_file = open(file_path, 'r')
            global_stats_attachment = MIMEText(global_stats_file.read(), _subtype='csv')
            global_stats_attachment.add_header("Content-Disposition", 'attachment', filename='global_statistics.csv')
            msg.attach(global_stats_attachment)
            try:
                server.sendmail(self.sender_email, to_email, msg.as_string())
            except (SMTPRecipientsRefused, SMTPHeloError, SMTPSenderRefused,
                    SMTPDataError, SMTPServerDisconnected) as e:
                print "Error:", e
        server.close()
