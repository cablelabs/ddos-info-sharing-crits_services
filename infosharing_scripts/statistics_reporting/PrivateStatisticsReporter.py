import csv
from datetime import datetime
from PrivateStatisticsCollector import PrivateStatisticsCollector

class PrivateStatisticsReporter:

    def __init__(self):
        self.collector = PrivateStatisticsCollector()

    def run(self):
        self.write_top_attacking_asns()
        self.write_submissions_per_period()
        self.write_submissions_per_owning_source()

    def write_top_attacking_asns(self):
        # Write additional statistics that are not to be emailed to participants.
        top_attacking_asn_filepath = self.reports_path + 'top_attacking_asns.csv'
        csv_file = open(top_attacking_asn_filepath, 'wb')
        stats_writer = csv.writer(csv_file)
        stats_writer.writerow(['ASN', 'Number of Events'])
        top_attacking_asn_counts = self.collector.top_attacking_asn_counts(10)
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
            submissions_counts = self.collector.count_submissions_per_period(period=period_iteration)
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

reporter = PrivateStatisticsReporter()
reporter.run()
