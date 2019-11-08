# -*- coding: utf-8 -*-
import gzip
import re
import sqlite3
import sys

from defusedxml import ElementTree


class IngestLogfile:
    """log ingestion class"""
    def __init__(self, conn):
        """
        :param conn: sqlite connection object
        """
        self.conn = conn

        self.jid_pattern = re.compile("^(?:([^\"&'/:<>@]{1,1023})@)?([^/@]{1,1023})(?:/(.{1,1023}))?$")
        self.message_pattern = re.compile(r'<message.*?</message>', re.DOTALL)

    def read(self, infile: list = None):
        """
        ingest method to split up the ingest file list, if necessary decompression and decoding are applied
        :param infile: list containing log filenames to be ingested
        """
        magic_number = b"\x1f\x8b\x08"

        # iterate over all infile elements
        for element in infile:

            try:
                # open file in binary mode
                with open(element, "rb") as infile:
                    content = infile.read()

            # in case of a missing file set content to an empty string
            except FileNotFoundError as err:
                content = ""
                print(err, file=sys.stderr)

            # if magic number is present decompress and decode file
            if content.startswith(magic_number):
                content = gzip.decompress(content).decode("utf-8")
            # in any other case read file normally
            else:
                content = content.decode("utf-8")

            # None catch
            if content is not None:
                log = re.findall(self.message_pattern, content)

                if log is not None:
                    self.db_import(log)

    def db_import(self, message_log: list):
        """
        import xml stanzas into database
        :param message_log: list of xml messages
        """
        for message in message_log:
            message_parsed = ElementTree.fromstring(message)

            # parse 'from' tag
            spam_from = message_parsed.get('from')
            match = self.jid_pattern.match(spam_from)
            (node, domain, resource) = match.groups()

            # stamp
            all_delay_tags = message_parsed.findall('.//{urn:xmpp:delay}delay')
            spam_time = None
            for tag in all_delay_tags:
                if "@" in tag.get("from"):
                    continue

                spam_time = tag.get('stamp')

            # body
            spam_body = message_parsed.find('{jabber:client}body')
            if spam_body is not None:
                spam_body = spam_body.text

            # format sql
            try:
                self.conn.execute('''INSERT INTO spam VALUES(:user, :domain, :spam_time, :spam_body);''',
                                  {"user": node, "domain": domain, "spam_time": spam_time, "spam_body": spam_body})
            except sqlite3.IntegrityError:
                pass
            finally:
                self.conn.commit()
