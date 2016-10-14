from multiprocessing import Process
import commands
import os, signal, time
import smtplib
from email.mime.text import MIMEText

import pymongo
from bson.timestamp import Timestamp

from crits.ips.ip import IP
from crits.comments.comment import Comment
from crits.comments.views import add_update_comment
from crits.core.crits_mongoengine import create_embedded_source, json_handler
from crits.core.user_tools import get_user_organization, user_sources
from crits.core.user import CRITsUser
from crits.vocabulary.objects import ObjectTypes

# global variables
process = None

# constants
use_oplog = True

def start_service():
    global process
    if process is None:
        process = Process(target=process_data, args=())
        process.start()
    else:
        try:
            os.kill(process.pid, signal.SIGKILL)
        except OSError:
            pass
        process.join()
        process = None

    is_processing_data = (process is not None)

    # Wrap 'is_processing_data' with str() because otherwise it doesn't appear in UI when false.
    return {'success': True,
            'html': '',
            'is_processing_data': str(is_processing_data)}

def process_data():
    if use_oplog:
        process_from_oplog()
    process_from_audit_log()

# oplog is capped collection, so it can be tailed
def process_from_oplog():
    client = pymongo.MongoClient()
    oplog = client.local.oplog.rs
    first_entry = oplog.find().sort('ts', pymongo.ASCENDING).limit(1).next()
    timestamp = Timestamp(1476479785, 2) #first_entry['ts']

    while True:
        cursor = oplog.find({'ts': {'$gt': timestamp},
                             'ns': 'crits.audit_log',
                             'o.type': 'IP'},
                            tailable=True,
                            await_data=True)
        cursor.add_option(8)
        while cursor.alive:
            for doc in cursor:
                timestamp = doc['ts']
                username = doc['o']['user']
                object_id = doc['o']['target_id']
                ip_object = IP.objects(id=object_id).first()
                if ip_object:
                    check_ip_object_asn(username, ip_object)
            time.sleep(1)

def check_ip_object_asn(username, ip_object):
    if ip_object.status == 'Analyzed':
        # already analyzed this IP object
        return
    arriving_asn = ip_object.asn
    ip_address = ip_object.ip
    correct_asn = DNSLookup(ip_address, 'IPv4 Address')
    if arriving_asn != correct_asn:
        ip_object.asn = correct_asn

        # remove old ASN Object(s)
        for o in ip_object.obj:
            if o.object_type == ObjectTypes.AS_NUMBER:
                ip_object.remove_object(ObjectTypes.AS_NUMBER, o.value)

        # add new ASN Object(s)
        for s in ip_object.source:
            ip_object.add_object(ObjectTypes.AS_NUMBER, correct_asn, s.name, '', '', username)
        add_flag_comment_to_ip(ip_object.id, username)
    ip_object.set_status('Analyzed')
    # potential looping problem because this will add another entry to the audit_log
    ip_object.save(username=username)

# based on comment_add() in crits/crits/comments/handlers.py
def add_flag_comment_to_ip(obj_id, analyst):
    """
    Add a new comment indicating the ASN was wrong.

    :param obj_id: The top-level ObjectId to add the comment to.
    :type obj_id: str
    :param analyst: The user adding the comment.
    :type analyst: str
    :returns: Nothing
    """

    comment = Comment()
    comment.comment = "Error: Incorrect ASN given to IP. Corrected by analysis."
    comment.parse_comment()
    comment.set_parent_object('IP', obj_id)
    comment.analyst = analyst
    #TODO: Is this line necessary?
    #comment.set_url_key(cleaned_data['url_key'])

    source = create_embedded_source(name=get_user_organization(analyst),
                                    analyst=analyst)
    comment.source = [source]
    comment.save(username=analyst)
    # this is silly :( in the comment object the dates are still
    # accurate to .###### seconds, but in the database are only
    # accurate to .### seconds. This messes with the template's ability
    # to compare creation and edit times.
    comment.reload()
    comment.comment_to_html()

# CURRENTLY NOT USED
def notify_user_incorrect_asn(username):
    user = CRITsUser.objects(username=username).first()
    if user and user.email:
        msg = MIMEText("Hey, you got the ASN wrong!")
        msg['Subject'] = "Hey, listen!"
        from_email = 'zane.hintzman@gmail.com'
        to_email = from_email
        msg['From'] = from_email
        msg['To'] = to_email

        # TODO: probably won't be able to send from a local server. Figure out how I did emails before.
        s = smtplib.SMTP('localhost')
        s.sendmail(from_email, [to_email], msg.as_string())
        s.quit()

def DNSLookup(ip, ip_type):
    ip_numbers = ip.split('.')
    # need to reverse the sections of the IP in order to make the correct request for this IP
    ip_numbers.reverse()
    reversed_ip = '.'.join(ip_numbers)

    start_time = time.time()
    if ip_type == 'IPv4 Address':
        output = commands.getstatusoutput("dig +short " + reversed_ip + ".origin.asn.shadowserver.org TXT")
    else:
        # TODO Figure out how to convert IPv6 address to 'nibble' format. Also, not sure if Shadowserver URL similar.
        output = commands.getstatusoutput("dig +short " + reversed_ip + ".origin6.asn.cymru.com TXT")
    asn = GetASNFromOutput(output)
    return asn

def GetASNFromOutput(output):
    asn = output[1].split("|", 1)[0]  # ASN is the first value
    return asn.strip().replace("\"", "")  # remove extra characters

def WhoisLookup(ip):
    command_string = "whois -h asn.shadowserver.org origin " + ip

    start_time = time.time()
    output = commands.getstatusoutput(command_string)
    duration = time.time() - start_time

    asn = GetASNFromWhoisOutput(output)
    return asn

def GetASNFromWhoisOutput( output):
    asn = output[0].split("|", 1)[0]  # ASN is the first value
    return asn.strip()

# audit_log not tailable because it isn't a capped collection
def process_from_audit_log():
    client = pymongo.MongoClient()
    audit_log = client.crits.audit_log
    first_entry = audit_log.find().sort('date', pymongo.ASCENDING).limit(1).next()
    date = first_entry['date']

    while True:
        cursor = audit_log.find({'date': {'$gt': date}})
        while cursor.alive:
            for doc in cursor:
                date = doc['date']
                # TODO: Do something...
            time.sleep(1)