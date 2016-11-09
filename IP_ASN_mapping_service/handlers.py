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
from crits.core.handlers import add_releasability, add_releasability_instance
from crits.core.source_access import SourceAccess
from crits.core.user_tools import get_user_organization, user_sources
from crits.core.user import CRITsUser
from crits.vocabulary.objects import ObjectTypes
from crits.vocabulary.status import Status

# global variables
process = None

# constants
use_oplog = True

def start_or_stop_service():
    global process
    if process is None:
        process = Process(target=process_data, args=())
        process.start()
    else:
        try:
            pid = process.pid
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        process.join()
        process = None

    # Wrap 'is_process_running()' with str() because otherwise it doesn't appear in UI when false.
    return {'success': True,
            'html': '',
            'process_status': process_status()}

def process_status():
    """
    Returns 'Running" if process is running, and 'Stopped' otherwise.
    :return: 'Running' or 'Stopped'
    """
    if (process is not None):
        return 'Running'
    return 'Stopped'

def process_data():
    if use_oplog:
        process_from_oplog()
    process_from_audit_log()
    return

# oplog is capped collection, so it can be tailed
def process_from_oplog():
    client = pymongo.MongoClient()
    oplog = client.local.oplog.rs
    first_entry = oplog.find().sort('ts', pymongo.ASCENDING).limit(1).next()
    timestamp = Timestamp(1477956427, 1) #first_entry['ts']

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
                if ip_object and ip_object.status != Status.ANALYZED:
                    if not check_and_update_ip_object_asn(ip_object, username):
                        add_flag_comment_to_ip(ip_object, username)
                    add_additional_sources(ip_object, username)
                    ip_object.set_status(Status.ANALYZED)
                    # potential looping problem because this will add another entry to the audit_log
                    ip_object.save(username=username)
            time.sleep(1)
    return

# True iff an update was not required
def check_and_update_ip_object_asn(ip_object, username):
    arriving_asn = ip_object.asn
    ip_address = ip_object.ip
    correct_asn = DNSLookup(ip_address, 'IPv4 Address')
    if arriving_asn != correct_asn:
        update_ip_object_asn(ip_object, correct_asn, username)
        return False
    return True

def DNSLookup(ip, ip_type):
    ip_numbers = ip.split('.')
    # need to reverse the sections of the IP in order to make the correct request for this IP
    ip_numbers.reverse()
    reversed_ip = '.'.join(ip_numbers)
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

def update_ip_object_asn(ip_object, asn, username):
    ip_object.asn = asn

    # Remove old AS Number object(s)

    # To prevent skipping objects in ip_object.obj due to removing objects, store list of ASNs to remove.
    asn_values = []
    for o in ip_object.obj:
        if o.object_type == ObjectTypes.AS_NUMBER:
            asn_values.append(o.value)
    for asn_value in asn_values:
        ip_object.remove_object(ObjectTypes.AS_NUMBER, asn_value)

    # add new AS Number object
    for s in ip_object.source:
        ip_object.add_object(ObjectTypes.AS_NUMBER, asn, s.name, '', '', username)
    return

# based on comment_add() in crits/crits/comments/handlers.py
def add_flag_comment_to_ip(ip_object, analyst):
    """
    Add a new comment indicating the ASN was wrong.

    :param ip_object: The top-level IP object to add the comment to.
    :type ip_object: IP
    :param analyst: The user adding the comment.
    :type analyst: str
    :returns: Nothing
    """

    comment = Comment()
    comment.comment = "Error: Incorrect ASN given to IP. Corrected by analysis."
    comment.parse_comment()
    comment.set_parent_object('IP', ip_object.id)
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
    return

def add_additional_sources(ip_object, username):
    try:
        asn = int(ip_object.asn)
    except ValueError:
        return
    is_asn_in_sources = False
    for src in ip_object.source:
        source_objects = SourceAccess.objects().filter(name=src.name)
        for src_obj in source_objects:
            if asn in src_obj.asns:
                is_asn_in_sources = True
                break
    if not is_asn_in_sources:
        source = asn_to_source_name(asn)
        if source:
            source = [create_embedded_source(source,
                                             reference=None,
                                             method=None,
                                             analyst=username)]
            if source:
                for s in source:
                    ip_object.add_source(s)
                    add_releasability('IP', ip_object.id, s.name, username)
                    add_releasability_instance('IP', ip_object.id, s.name, username)

def asn_to_source_name(asn):
    sources = SourceAccess.objects()
    for src in sources:
        if asn in src.asns:
            return src.name



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

# CURRENTLY NOT USED
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

# CURRENTLY NOT USED
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