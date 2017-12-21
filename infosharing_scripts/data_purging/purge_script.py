import json
import pendulum
import sys
from OldDataPurger import OldDataPurger

config_filename = '/data/configs/duration_config.json'
with open(config_filename, 'r') as config_file:
    configs = json.load(config_file)
    months = configs['months']
    days = configs['days']
    today_datetime = pendulum.today('UTC')
    print "Today:", today_datetime
    earliest_datetime = today_datetime.subtract(months=months, days=days)
    print "Earliest Allowed Date:", earliest_datetime
if earliest_datetime is None:
    sys.exit("Error: earliest_datetime not defined.")

# Note: Event though IDE may say 'earliest_datetime' is a Pendulum object, it still counts as a datetime.
purger = OldDataPurger()
purger.delete_data_before_datetime(earliest_datetime)
