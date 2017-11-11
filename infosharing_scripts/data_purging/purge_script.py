from OldDataPurger import OldDataPurger

purger = OldDataPurger()
purger.delete_old_ips(months=0, days=3)
purger.remove_events_with_no_ip()
