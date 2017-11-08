import os
from datetime import datetime, timedelta
from multiprocessing import Pool

os.environ['DJANGO_SETTINGS_MODULE'] = 'crits.settings'

from crits.core.user_tools import get_user_organization
from crits.ips.ip import IP


def update_ip_object(ip_object):
    analyst = 'analysis_autofill'
    try:
        # To prevent skipping objects while iterating through sub-objects, store list of objects to remove later.
        # Note: In this case, I expect that there will be only one value to remove.
        previous_object_values = []
        for o in ip_object.obj:
            if o.object_type == 'Last Time Received':
                previous_object_values.append(o.value)
        last_time_seen = ''
        for previous_value in previous_object_values:
            last_time_seen = previous_value
            ip_object.remove_object('Last Time Received', previous_value)
        last_time_seen_datetime = datetime.strptime(last_time_seen, "%Y-%m-%dT%H:%M:%S.%fZ")
        # Convert the time to UTC. Hard-coded increment of 7 hours, because we know the issue occurred on a machine
        # running on MST (UTC-7).
        last_time_seen_datetime += timedelta(hours=7)
        last_time_seen = last_time_seen_datetime.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        ip_object.add_object('Last Time Received', last_time_seen, get_user_organization(analyst), '', '', analyst)
    except Exception as e:
        raise
    return


class UpdateLastTimeModified:
    """
    The purpose of this script is to update the "lastTimeModified" field of each IP in the database, because the code
    originally set this field to the current time in the machine's timezone (MST).
    """

    def run(self):
        # TODO: should we somehow mark the IP addresses to indicate we changed it successfully?
        # TODO: what should we do if the process gets cut-off part-way through?
        ip_objects = IP.objects()
        pool = Pool(10)
        pool.map(update_ip_object, ip_objects)

update = UpdateLastTimeModified()
#update.run()
