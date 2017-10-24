import csv
from datetime import datetime
import json, os, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper


class CritsStatisticsReporter:

    def __init__(self):
        self.wrapper = MongoDBFunctionsWrapper()
        self.reports_path = ''
        self.global_statistics_path = ''
        self.email_user_statistics = False
        self.user_statistics_path_prefix = ''

    def run(self):
        full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        time_now = datetime.now()
        time_now_str = time_now.strftime(full_time_format)
        self.reports_path = 'reports/'+time_now_str+'/'
        os.mkdir(self.reports_path)
        self.global_statistics_path = self.reports_path + 'global_statistics.csv'
        self.user_statistics_path_prefix = self.reports_path + 'user_statistics_'
        #self.write_global_statistics()
        #self.write_user_statistics()
        #self.email_statistics()
        # NOTE: Stats below are optional, and not sent to users.
        self.write_top_attacking_asns()
        #self.write_submissions_per_period()
        #self.write_submissions_per_owning_source()

    def write_global_statistics(self):
        csv_file = open(self.global_statistics_path, 'wb')
        stats_writer = csv.writer(csv_file)
        #stats_writer.writerow(['Statistic', 'Value'])

        total_ips = self.wrapper.count_ips()
        stats_writer.writerow(['Total # of IPs', total_ips])
        print "Wrote total number of IPs."
        total_events = self.wrapper.count_events()
        stats_writer.writerow(['Total # of Events', total_events])
        print "Wrote total number of Events."
        number_ips_reported_by_many_sources = self.wrapper.count_ips_multiple_sources()
        stats_writer.writerow(['# of IPs reported by multiple data providers', number_ips_reported_by_many_sources])
        print "Wrote number of IPs reported by more than one data provider."
        number_events_multiple_sources = self.wrapper.count_events_multiple_sources()
        stats_writer.writerow(['# of Events for IPs reported by multiple data providers', number_events_multiple_sources])
        print "Wrote number of Events for IPs reported by more than one data provider."

        # TODO: Make query for attack types with multiple reporters faster.
        # stats_writer.writerow([])
        # stats_writer.writerow(['Top Attack Types'])
        # stats_writer.writerow(['Attack Type', 'Number of Events'])
        # start = datetime.now()
        # top_attack_type_counts = self.wrapper.count_events_top_attack_types_multiple_sources_v3(10)
        # duration = datetime.now() - start
        # print "Query Time:", duration
        # #sorted(top_attack_type_counts.iteritems(), key=lambda (k, v): v, reverse=True)
        # #for attack_type, count in top_attack_type_counts:
        # for attack_type, count in sorted(top_attack_type_counts.iteritems(), key=lambda (k, v): v, reverse=True):
        #     stats_writer.writerow([attack_type, count])
        # print "Wrote top 10 attack types."

        stats_writer.writerow([])
        stats_writer.writerow(['Top Attacking Countries'])
        stats_writer.writerow(['Country', 'Number of Events'])
        top_attacking_country_counts = self.wrapper.count_events_top_attacking_countries_multiple_reporters(10)
        for country, count in top_attacking_country_counts:
            stats_writer.writerow([country, count])
        print "Wrote top 10 attacking countries."
        csv_file.close()

    def write_user_statistics(self):
        for user in self.wrapper.find_users():
            username = user['username']
            user_statistics_path = self.user_statistics_path_prefix + username + '.csv'
            csv_file = open(user_statistics_path, 'wb')
            stats_writer = csv.writer(csv_file)
            # TODO: consider only submissions they did in the last week or last 7 days
            submissions_counts = self.wrapper.count_recent_submissions_from_user(username)
            stats_writer.writerow(['IPs submitted', submissions_counts['ips']])
            stats_writer.writerow(['Events submitted', submissions_counts['events']])
            csv_file.close()
            print 'Wrote number of submissions per user.'

    def email_statistics(self):
        for user in self.wrapper.find_users():
            username = user['username']
            to_email = user['email']
            # Note: '40.97.138.66' is the IP address for 'smtp-mail.outlook.com'.
            server = smtplib.SMTP(host='40.97.138.66', port=587)
            server.starttls()
            credentials_file = open('credentials.json', 'r')
            credentials = json.load(credentials_file)
            from_email = credentials['address']
            password = credentials['password']
            server.login(from_email, password)
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Date'] = formatdate(localtime=True)
            msg['Subject'] = "Statistics for User '" + username + "'"

            global_stats_file = open(self.global_statistics_path, 'r')
            global_stats_attachment = MIMEText(global_stats_file.read(), _subtype='csv')
            global_stats_attachment.add_header("Content-Disposition", 'attachment', filename='global_statistics.csv')
            msg.attach(global_stats_attachment)

            user_stats_filepath = self.user_statistics_path_prefix + username + '.csv'
            user_stats_file = open(user_stats_filepath, 'r')
            user_stats_attachment = MIMEText(user_stats_file.read(), _subtype='csv')
            user_stats_filename = 'user_statistics_'+username+'.csv'
            user_stats_attachment.add_header("Content-Disposition", 'attachment', filename=user_stats_filename)
            msg.attach(user_stats_attachment)
            try:
                result = server.sendmail(from_email, to_email, msg.as_string())
            except Exception as e:
                print e
            server.close()

    def write_top_attacking_asns(self):
        # Write additional statistics that are not to be emailed to participants.
        top_attacking_asn_filepath = self.reports_path + 'top_attacking_asns.csv'
        csv_file = open(top_attacking_asn_filepath, 'wb')
        stats_writer = csv.writer(csv_file)
        stats_writer.writerow(['ASN', 'Number of Events'])
        top_attacking_asn_counts = self.wrapper.top_attacking_asn_counts(10)
        rank = 1
        for as_number, count in sorted(top_attacking_asn_counts.iteritems(), key=lambda (k,v): v, reverse=True):
            stats_writer.writerow([as_number, count])
            rank += 1
        print "Wrote top 10 attacking ASNs."
        csv_file.close()

    def write_submissions_per_period(self, time_now_str):
        period_iterations = ['day', 'month']
        for period_iteration in period_iterations:
            csv_file = open('detailed_statistics/submissions_per_'+period_iteration+'_'+time_now_str+'.csv', 'wb')
            stats_writer = csv.writer(csv_file)
            stats_writer.writerow([period_iteration, 'IPs', 'Events'])
            submissions_counts = self.wrapper.count_submissions_per_period(period=period_iteration)
            for period, counts in sorted(submissions_counts.iteritems()):
                ips_count = counts['ips']
                events_count = counts['events']
                stats_writer.writerow([period, ips_count, events_count])
            csv_file.close()
            print 'Wrote number of submissions per ' + period_iteration + '.'

    def write_submissions_per_owning_source(self, time_now_str):
        csv_file = open('detailed_statistics/submissions_per_owning_source_'+time_now_str+'.csv', 'wb')
        stats_writer = csv.writer(csv_file)
        stats_writer.writerow(['Source Name', 'IPs', 'Events'])
        submissions_counts = self.wrapper.count_submissions_per_owning_source()
        for source_name, counts in sorted(submissions_counts.iteritems()):
            ips_count = counts['ips']
            events_count = counts['events']
            stats_writer.writerow([source_name, ips_count, events_count])
        csv_file.close()
        print 'Wrote number of submissions per owning source.'


stats_reporter = CritsStatisticsReporter()
stats_reporter.run()
