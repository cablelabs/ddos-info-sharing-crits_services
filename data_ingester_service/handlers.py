import pendulum
from pymongo import MongoClient


def save_ingest_data(analyst, source, ingest_data_entries):
    """
    Saves multiple IP objects to temporary database using the ingest data.

    :param analyst: The analyst who sent the POST message for the IP objects.
    :type analyst: str
    :param source: The source of the POST message for the IP objects.
    :type source: str
    :param ingest_data_entries: A list of objects with data about attacks from IP addresses.
    :type ingest_data_entries: list of dictionaries, each conforming to an 'ingestData' object in the definitions of the data ingester payload schema
    :return: (nothing)
    """
    client = MongoClient()
    staging_ips = client.staging_crits_data.ips
    for ingest_data_entry in ingest_data_entries:
        ingest_data_entry['analyst'] = analyst
        ingest_data_entry['source'] = source
        ingest_data_entry['timeReceived'] = pendulum.now('UTC')
        ingest_data_entry['isProcessed'] = False
        staging_ips.insert_one(ingest_data_entry)
    return
