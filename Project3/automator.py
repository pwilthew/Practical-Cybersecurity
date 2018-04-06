#!/home/patrixia/Documents/Project3/venv/bin/python3.6
"""Practical Cybersecurity: Project 3.
Student: Patricia Wilthew."""
import os
import pymysql
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pytz import timezone

def read_notices(dir_with_notices):
    """"For all text files (notices) in dir_with_notices,
    return a list of dictionaries containing the <Source>
    tag. One dictionary per file. Each dictionary looks like:
    
    {'timestamp': x,
     'ip': x,
     'port': x,
     'dest_ip': x,
     'dest_port': x 
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
                'timestamp': utc_to_est(source[0].text),
                'ip': source[1].text,
                'port': source[2].text,
                'dest_ip': source[3].text,
                'dest_port': source[4].text
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


def get_username_of_mac(mac):
    """Given a MAC address, return the user associated with it."""
    query = """SELECT contact 
               FROM contactinfo 
               WHERE mac_string='%s' 
            """ % mac

    conn = get_db_connection()

    with conn.cursor() as cursor:
        cursor.execute(query)

    return cursor.fetchone()[0]


def utc_to_est(date_string):
    """Given a timestamp string in UTC timezone, convert it
    to an EST datetime object and return it."""
    # Create a datetime object with date_string
    datetime_obj = datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%SZ")
    
    # Add (define) timezone of object
    datetime_utc = datetime_obj.replace(tzinfo=timezone('UTC'))

    # Convert to EST
    datetime_est = datetime_utc.astimezone(timezone('US/Eastern'))

    # Remove timezone 
    new_datetime = datetime_est.replace(tzinfo=None)

    return new_datetime


def get_nat_log_filename(timestamp):
    """"Given a datetime object, return the file name that contains
    the NAT logs that occurred before that datetime.
    For example, the logs for 10:54 AM will be in the file for 
    11th hour; nat.csv.2016032111.csv.gz."""
    file_names = os.listdir("nat_logs")


def get_db_connection():
    """Return a connection to logs_db database."""
    return pymysql.connect(
        host="localhost", 
        user="myuser",
        password="mypassword",
        db="logs_db")


def main():
    # Get directory that contains the notices' files from command line
    dir_with_notices = sys.argv[1]

    # Get notices data
    list_of_dictionaries_of_notices = read_notices(dir_with_notices)

    print(list_of_dictionaries_of_notices)

    #print(get_username_of_mac('ff:ff:55:d2:c4:21'))
    #print(utc_to_est("2016-03-21T14:54:27Z"))


    return


if __name__ == "__main__":
    main()