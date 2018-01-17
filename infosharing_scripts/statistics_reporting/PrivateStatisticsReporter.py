import csv
import json
import smtplib
from smtplib import SMTPRecipientsRefused, SMTPHeloError, SMTPSenderRefused, SMTPDataError, SMTPServerDisconnected
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import pendulum
from PrivateStatisticsCollector import PrivateStatisticsCollector


class PrivateStatisticsReporter:
    """
    The purpose of this script is to send internal emails with additional statistics about the system. The information
    in these emails should not be disclosed to participants.
    """

    def __init__(self):
        self.collector = PrivateStatisticsCollector()
        configs_directory = "/data/configs/"
        self.reports_directory = "/data/reports/"
        reporting_config_filename = configs_directory + "reporting_config.json"
        self.statistics_message_filename = configs_directory + 'additional_statistics_message.txt'
        with open(reporting_config_filename, 'r') as reporting_config_file:
            configs = json.load(reporting_config_file)
            self.sender_email = str(configs['sender_email'])
            self.report_file_recipients = configs['recipients']
            self.password = str(configs['password'])

    def run(self):
        # Store today's date to make sure all calculations are done relative to this date.
        today_utc = pendulum.today('UTC')
        yesterday_utc_date_string = today_utc.subtract(days=1).to_date_string()
        private_statistics_file_path = self.reports_directory+'additional_statistics_through_'+yesterday_utc_date_string+'.csv'
        yesterday_end = today_utc.subtract(microseconds=1)
        self.write_statistics(private_statistics_file_path, yesterday_end)
        self.email_statistics(private_statistics_file_path)

    def write_statistics(self, file_path, end_time):
        """
        Write relevant statistics to CSV file.
        :param file_path: The name of the CSV file to which data is written.
        :param end_time: The time up to which all statistics are measured, inclusive.
        :type end_time: datetime (preferably created using 'pendulum' library)
        :return:
        """
        with open(file_path, 'wb') as csv_file:
            stats_writer = csv.writer(csv_file)
            # TODO: When AS Name lookup working, add that to statistics
            stats_writer.writerow(['ASN', 'Number of Events'])
            start_time = pendulum.now()
            top_attacking_asn_counts = self.collector.count_events_top_attacking_asns_multiple_reporters(end_time)
            duration = pendulum.now() - start_time
            print "Time to Count Top ASNs:", duration
            for asn, count in top_attacking_asn_counts:
                stats_writer.writerow([asn, count])
            print "Wrote top 10 attacking ASNs."

    def email_statistics(self, file_path):
        server = smtplib.SMTP(host='smtp.office365.com', port=587)
        server.ehlo()
        server.starttls()
        server.login(self.sender_email, self.password)
        for email in self.report_file_recipients:
            msg = MIMEMultipart()
            with open(self.statistics_message_filename, 'r') as message_file_message:
                body_text = message_file_message.read()
            with open(file_path, 'r') as stats_file:
                stats_reader = csv.reader(stats_file)
                for row in stats_reader:
                    asn = row[0]
                    if row[0] == 'ASN':
                        continue
                    body_text += "ASN: " + asn + "\n"
                    number_of_events = row[1]
                    body_text += "Number of Events: " + number_of_events + "\n\n"
            msg.attach(MIMEText(body_text))
            msg['From'] = self.sender_email
            msg['To'] = email
            msg['Date'] = formatdate(localtime=True)
            msg['Subject'] = "DDoS Information Sharing Additional Statistics"
            try:
                server.sendmail(self.sender_email, email, msg.as_string())
            except (SMTPRecipientsRefused, SMTPHeloError, SMTPSenderRefused,
                    SMTPDataError, SMTPServerDisconnected) as e:
                print "Error:", e
        server.close()

    # def write_submissions_per_period(self, time_now_str):
    #     period_iterations = ['day', 'month']
    #     for period_iteration in period_iterations:
    #         csv_file = open('detailed_statistics/submissions_per_'+period_iteration+'_'+time_now_str+'.csv', 'wb')
    #         stats_writer = csv.writer(csv_file)
    #         stats_writer.writerow([period_iteration, 'IPs', 'Events'])
    #         submissions_counts = self.collector.count_submissions_per_period(period=period_iteration)
    #         for period, counts in sorted(submissions_counts.iteritems()):
    #             ips_count = counts['ips']
    #             events_count = counts['events']
    #             stats_writer.writerow([period, ips_count, events_count])
    #         csv_file.close()
    #         print 'Wrote number of submissions per ' + period_iteration + '.'
    #
    # def write_submissions_per_owning_source(self, time_now_str):
    #     csv_file = open('detailed_statistics/submissions_per_owning_source_'+time_now_str+'.csv', 'wb')
    #     stats_writer = csv.writer(csv_file)
    #     stats_writer.writerow(['Source Name', 'IPs', 'Events'])
    #     submissions_counts = self.wrapper.count_submissions_per_owning_source()
    #     for source_name, counts in sorted(submissions_counts.iteritems()):
    #         ips_count = counts['ips']
    #         events_count = counts['events']
    #         stats_writer.writerow([source_name, ips_count, events_count])
    #     csv_file.close()
    #     print 'Wrote number of submissions per owning source.'
