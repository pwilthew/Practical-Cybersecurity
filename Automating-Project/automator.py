#!/home/patrixia/Documents/Project3/venv/bin/python3.6
"""Practical Cybersecurity: Project 3.
Student: Patricia Wilthew."""
import os
import pymysql
import re
import subprocess
import socket
import struct
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pytz import timezone

def read_notices(dir_with_notices):
    """"For all text files (notices) in dir_with_notices,
    return a list of dictionaries containing data in the <Source>
    tag. One dictionary per file. Each dictionary looks as follows:
    
    {"timestamp": x,
     "ip": x,
     "port": x,
     "dest_ip": x,
     "dest_port": x 
    }
    
    Note that these text files contain xml formatted data.
    """
    list_of_dictionaries_of_notices = []

    for filename in os.listdir(dir_with_notices):
        # Get content of every file in directory
        file_content = open(dir_with_notices + "/" + filename, "r").read()

        # Get root of XML after stripping out non-XML lines
        root = ET.fromstring(strip_regular_text_from_xml(file_content))

        # Get the child named "Source" of root
        source = root[3]

        # Get children of "Source"
        dic = {
                "timestamp": utc_to_est(source[0].text),
                "ip": source[1].text,
                "port": source[2].text,
                "dest_ip": source[3].text,
                "dest_port": source[4].text,
                "notice_filename": filename
            }

        # Add recently created dictionary to the list
        list_of_dictionaries_of_notices.append(dic)

    return list_of_dictionaries_of_notices


def strip_regular_text_from_xml(data):
    """Given the content of a text file (a string), return only
    its xml lines as one string."""

    # List to store XML lines
    new_data = []

    # Keep lines that start with < and append them to new_data
    for line in data.splitlines():
        if line.strip().startswith("<"):
            new_data.append(line)

    # Convert list to string and return it
    return "\n".join(new_data)


def utc_to_est(date_string):
    """Given a timestamp string in UTC timezone, convert it
    to an EST datetime object, and then to a timestamp string
    with the format "%Y-%m-%dT%H:%M:%S" and return it."""

    # Create a datetime object with date_string
    datetime_obj = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%SZ")
    
    # Add (define) timezone of object
    datetime_utc = datetime_obj.replace(tzinfo=timezone("UTC"))

    # Convert to EST
    datetime_est = datetime_utc.astimezone(timezone("US/Eastern"))

    return datetime_est.strftime("%Y-%m-%dT%H:%M:%S")


def timestamp_to_object(timestamp):
   """Given a timestamp string with the format "%Y-%m-%dT%H:%M:%S",
   return a datetime object."""
   return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")


def get_nat_log_filename(timestamp):
    """"Given a timestamp string, return the file name that contains
    the NAT logs that occurred before that datetime.

    For example, the logs for 10:54 AM will be in the file for 
    11th hour; nat.csv.2016032111.csv.gz."""

    # Get only digits of timestamp (without the timezone, 
    # or last 4 digits)
    only_digits_string = "".join([x for x in timestamp if x.isdigit()][:-4])

    # Get the last digit of the string made of digits only
    last_digit = only_digits_string[-1]

    # Chop the last digit of the string, increment it, and append it back
    file_number = only_digits_string[:-1] + str(int(last_digit) + 1)

    file_to_search = "nat.csv.%s.csv.gz" % file_number

    # If this filename exists, return it
    if file_to_search in os.listdir("nat_logs"):
        print("Using " + color(file_to_search, "blue"))
        return "nat_logs/" + file_to_search

    print(color("A NAT logs file could not be found", "red"))
    return None


def get_pre_nat_ip(timestamp, ip, port, nat_logs_file):
    """Use NAT logs to identify the pre-NAT IP address
    associated with given timestamp, ip, and port."""

    # Filter NAT logs by IP and port 
    search_for = (ip + "," + port).encode()
    args = ["zgrep", search_for, nat_logs_file]
    ret, out, err = run_command(args)

    if ret:
        print(color("Post IP and port not found in NAT logs"))
        return None

    # Filter remaining logs by timestamp
    logs_of_ip = out.splitlines()
    filtered = [x for x in logs_of_ip if timestamp.encode() in x]
    number_of_entries = len(filtered)

    # Return ip and port if there was a best match for timestamp
    if number_of_entries >= 1: 
        entry_fields = filtered[0].split(b",")
        return entry_fields[2]

    # Else, search timestamps with a window of +/- 10 minutes
    timestamp = timestamp_to_object(timestamp)
    for entry in logs_of_ip:
        string = entry.split(b",")[0][:-10].decode("utf-8")
        entry_timestamp = timestamp_to_object(string)
        # If difference between entry time and wanted time is
        # 10 minutes or less, add to filtered
        if abs(timestamp - entry_timestamp) <= timedelta(minutes=10):
            filtered.append(entry)

    # If no success finding a close timestamp, return
    if not filtered:
        print(color("Closer timestamps not found in NAT logs"))
        return None

    # If there was more than one close timestamps, return
    # a list of tuples of (ip, port) associated with them
    possible_ips_ports = set()
    for entry in filtered:
        entry_fields = entry.split(b",")
        ip = entry_fields[2]
        port = entry_fields[3]
        possible_ips_ports.add(ip)

    return possible_ips_ports


def get_mac_address_with_ip(ip):
    """Given an IP address, return the MAC address
    associated with it in the DHCP logs."""
    ip_decimal = ip_to_decimal(ip)
    query = """SELECT mac_string 
               FROM dhcp 
               WHERE ip_decimal="%s" 
            """ % ip_decimal

    conn = get_db_connection()

    with conn.cursor() as cursor:
        cursor.execute(query)

    result_tuple = cursor.fetchone()

    if result_tuple:
        return result_tuple[0]
    else:
        return None


def get_username_of_mac(mac, ip):
    """Given a MAC address, return the user associated with it."""
    if ip.startswith("172.19."):
        query = """SELECT username 
                   FROM radacct 
                   WHERE CallingStationId="%s" 
                """ % mac
    else:
        query = """SELECT contact 
                   FROM contactinfo 
                   WHERE mac_string="%s" 
                """ % mac

    conn = get_db_connection()

    with conn.cursor() as cursor:
        cursor.execute(query)

    result_tuple = cursor.fetchone()

    if result_tuple:
        return result_tuple[0]
    else:
        return None


def ip_to_decimal(ip):
    """Given an IP address in string format, return
    its decimal representation."""
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


def get_db_connection():
    """Return a connection to logs_db database."""
    return pymysql.connect(
        host="localhost", 
        user="myuser",
        password="mypassword",
        db="logs_db")


def run_command(cmd_args):
    """Wrapper to run a command in subprocess."""
    proc = subprocess.Popen(cmd_args,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    return proc.returncode, out, err


def color(string, color="green"):
    if color == "green":
        return "\033[1;32m%s\033[1;0m" % string
    if color == "red":
        return "\033[1;31m%s\033[1;0m" % string
    if color == "yellow":
        return "\033[1;33m%s\033[1;0m" % string
    if color == "blue":
        return "\033[1;34m%s\033[1;0m" % string


def main():
    # Get directory that contains the notices" files from command line
    dir_with_notices = sys.argv[1]

    # Get notices data
    list_of_dictionaries_of_notices = read_notices(dir_with_notices)

    # Process each notice
    for notice in list_of_dictionaries_of_notices:
        print(color("-"*40))
        print("Processing notice: %s" % color(
                                    notice["notice_filename"], "yellow"))
        ip = notice["ip"]
        port = notice["port"]
        dest_ip = notice["dest_ip"]
        dest_port = notice["dest_port"]
        timestamp = notice["timestamp"]

        #print(timestamp, ip, port, dest_ip, dest_port)
        
        # Obtain nat_logs
        nat_logs = get_nat_log_filename(timestamp)

        # Skip notice if not NAT logs are found for 
        # its timestamp
        if nat_logs is None:
            continue

        # Get pre-NAT IP or IPs
        pre_nat_ip = get_pre_nat_ip(timestamp, ip, port, nat_logs)

        # Skip notice if a pre-NAT IP is not found
        if pre_nat_ip is None:
            continue

        users = set()

        # If there is only one possible pre-nat IP and port
        if type(pre_nat_ip) is bytes:
            mac = get_mac_address_with_ip(ip)
            if not (mac is None): 
                users.add(get_username_of_mac(mac, ip))

        # If there are multiple possible IPs and ports
        elif type(pre_nat_ip) is set:
            for ip in pre_nat_ip:
                mac = get_mac_address_with_ip(ip)
                if not (mac is None):
                    users.add(get_username_of_mac(mac, ip))

        if users:
            print(color("User(s) infected with malware: ", "red"))
            for user in users:
                print(user)

    print(color("-"*40))

    return


if __name__ == "__main__":
    main()