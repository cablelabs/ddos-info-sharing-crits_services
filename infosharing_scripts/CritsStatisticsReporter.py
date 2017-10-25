import csv
from datetime import datetime
import json, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from MongoDBFunctionsWrapper import MongoDBFunctionsWrapper


class CritsStatisticsReporter:

    def __init__(self):
        self.wrapper = MongoDBFunctionsWrapper()

    def run(self):
        full_time_format = '%Y-%m-%dT%H:%M:%S.%fZ'
        time_now = datetime.now()
        time_now_str = time_now.strftime(full_time_format)
        self.write_global_stats(time_now_str)
        self.write_user_statistics(time_now_str)
        #self.email_statistics(time_now_str)
        # NOTE: Stats below are optional, and not sent to users.
        self.write_top_attacking_asns(time_now_str)
        self.write_submissions_per_period(time_now_str)
        self.write_submissions_per_owning_source(time_now_str)

    ### File Writing Functions ###

    def write_global_stats(self, time_now_str):
        csv_file = open('global_statistics_' + time_now_str + '.csv', 'wb')
        stats_writer = csv.writer(csv_file)
        stats_writer.writerow(['Statistic', 'Value'])

        total_ips = self.wrapper.count_ips()
        stats_writer.writerow(['Total # of IPs', total_ips])
        print "Wrote total number of IPs."

        total_events = self.wrapper.count_events()
        stats_writer.writerow(['Total # of Events', total_events])
        print "Wrote total number of Events."

        number_ips_reported_by_many_sources = self.wrapper.count_ips_reported_by_multiple_sources()
        stats_writer.writerow(['# of IPs reported by multiple data providers', number_ips_reported_by_many_sources])
        print "Wrote number of IPs reported by more than one data provider."

        stats_writer.writerow([])
        stats_writer.writerow(['Top Attack Types'])
        stats_writer.writerow(['Attack Type', 'Number of Events'])
        top_attack_type_counts = self.wrapper.top_attack_type_counts(10)
        rank = 1
        for attack_type, count in sorted(top_attack_type_counts.iteritems(), key=lambda (k, v): v, reverse=True):
            stats_writer.writerow([attack_type, count])
            rank += 1
        print "Wrote top 10 attack types."

        stats_writer.writerow([])
        stats_writer.writerow(['Top Attacking Countries'])
        stats_writer.writerow(['Country', 'Number of Events'])
        top_attacking_country_counts = self.wrapper.top_attacking_country_counts(10)
        rank = 1
        for country, count in sorted(top_attacking_country_counts.iteritems(), key=lambda (k, v): v, reverse=True):
            stats_writer.writerow([country, count])
            rank += 1
        print "Wrote top 10 attacking countries."
        csv_file.close()

    def write_user_statistics(self, time_now_str):
        for user in self.wrapper.find_users():
            username = user['username']
            csv_file = open('detailed_statistics/user_statistics_'+username+'_'+time_now_str+'.csv', 'wb')
            stats_writer = csv.writer(csv_file)
            submissions_counts = self.wrapper.count_submissions_from_given_user(username)
            stats_writer.writerow(['IPs submitted', submissions_counts['ips']])
            stats_writer.writerow(['Events submitted', submissions_counts['events']])
            csv_file.close()
            print 'Wrote number of submissions per user.'
            # TODO: add more personal statistics, but I don't know what to add.

    def email_statistics(self, time_now_str):
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

            global_stats_filename = 'global_statistics_'+time_now_str+'.csv'
            global_stats_file = open(global_stats_filename, 'r')
            global_stats_attachment = MIMEText(global_stats_file.read(), _subtype='csv')
            global_stats_attachment.add_header("Content-Disposition", 'attachment', filename=global_stats_filename)
            msg.attach(global_stats_attachment)

            user_stats_filename = 'user_statistics_'+username+'_'+time_now_str+'.csv'
            user_stats_filepath = 'detailed_statistics/' + user_stats_filename
            user_stats_file = open(user_stats_filepath, 'r')
            user_stats_attachment = MIMEText(user_stats_file.read(), _subtype='csv')
            user_stats_attachment.add_header("Content-Disposition", 'attachment', filename=user_stats_filename)
            msg.attach(user_stats_attachment)
            try:
                result = server.sendmail(from_email, to_email, msg.as_string())
            except Exception as e:
                print e
            server.close()

    def write_top_attacking_asns(self, time_now_str):
        # Write additional statistics that are not to be emailed to participants.
        csv_file = open('detailed_statistics/top_attacking_asns_'+time_now_str+'.csv', 'wb')
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
