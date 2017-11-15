import csv
from datetime import datetime
import json, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from GlobalStatisticsCollector import GlobalStatisticsCollector


class GlobalStatisticsReporter:

    def __init__(self):
        self.collector = GlobalStatisticsCollector()
        self.global_statistics_message_filename = 'global_statistics_message.txt'

    def run(self):
        # Each file is named using the timestamp of the time the file was created (approximately).
        full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        time_now_str = datetime.now().strftime(full_time_format)
        global_statistics_file_path = 'reports/global_statistics_'+time_now_str+'.csv'
        self.write_statistics(global_statistics_file_path)
        #self.email_statistics()

    def write_statistics(self, file_path):
        full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        csv_file = open(file_path, 'wb')
        stats_writer = csv.writer(csv_file)
        stats_writer.writerow(['Statistic', 'Value', 'Time Collected'])
        try:
            time_collected_str = datetime.now().strftime(full_time_format)
            total_ips = self.collector.count_ips()
            stats_writer.writerow(['Total # of IPs', total_ips, time_collected_str])
            print "Wrote total number of IPs."

            time_collected_str = datetime.now().strftime(full_time_format)
            total_events = self.collector.count_events()
            stats_writer.writerow(['Total # of Events', total_events, time_collected_str])
            print "Wrote total number of Events."

            time_collected_str = datetime.now().strftime(full_time_format)
            total_ips_multiple_reporters = self.collector.count_ips_multiple_reporters()
            stats_writer.writerow(['# of IPs reported by multiple data providers', total_ips_multiple_reporters, time_collected_str])
            print "Wrote number of IPs reported by more than one data provider."

            time_collected_str = datetime.now().strftime(full_time_format)
            total_events_multiple_reporters = self.collector.count_events_multiple_reporters()
            stats_writer.writerow(['# of Events for IPs reported by multiple data providers', total_events_multiple_reporters, time_collected_str])
            print "Wrote number of Events for IPs reported by more than one data provider."

            stats_writer.writerow([])
            stats_writer.writerow(['Top Attack Types'])
            stats_writer.writerow(['Attack Type', 'Number of Events'])
            #top_attack_type_counts = self.collector.count_events_top_attack_types_multiple_reporters()
            #for attack_type, count in top_attack_type_counts:
            #    stats_writer.writerow([attack_type, count])
            print "Wrote top 10 attack types."

            stats_writer.writerow([])
            stats_writer.writerow(['Top Attacking Countries'])
            stats_writer.writerow(['Country', 'Number of Events'])
            top_attacking_country_counts = self.collector.count_events_top_attacking_countries_multiple_reporters()
            for country, count in top_attacking_country_counts:
                stats_writer.writerow([country, count])
            print "Wrote top 10 attacking countries."
        finally:
            csv_file.close()

    def email_statistics(self, file_path):
        for user in self.collector.find_users():
            username = user['username']
            to_email = user['email']
            # Note: '40.97.138.66' is the IP address for 'smtp-mail.outlook.com'.
            server = smtplib.SMTP(host='40.97.138.66', port=587)
            server.starttls()
            credentials_file = open('reporting_config.json', 'r')
            credentials = json.load(credentials_file)
            from_email = credentials['address']
            password = credentials['password']
            server.login(from_email, password)
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Date'] = formatdate(localtime=True)
            msg['Subject'] = "Statistics for User '" + username + "'"

            global_stats_file = open(file_path, 'r')
            global_stats_attachment = MIMEText(global_stats_file.read(), _subtype='csv')
            global_stats_attachment.add_header("Content-Disposition", 'attachment', filename='global_statistics.csv')
            msg.attach(global_stats_attachment)

            try:
                result = server.sendmail(from_email, to_email, msg.as_string())
            except Exception as e:
                print e
            server.close()


reporter = GlobalStatisticsReporter()
reporter.run()
