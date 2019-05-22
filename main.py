#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import re
import sqlite3

import tabulate
from defusedxml import ElementTree


class AbuseReport:
	"""Ingestation script for ejabberd spam logs"""

	def __init__(self, arguments):
		self.infile = arguments.infile
		self.domain = arguments.domain
		self.conn = sqlite3.connect('spam.db')

		self.jid_pattern = re.compile("^(?:([^\"&'/:<>@]{1,1023})@)?([^/@]{1,1023})(?:/(.{1,1023}))?$")
		self.message_pattern = re.compile(r'<message.*?</message>', re.DOTALL)

	def main(self):
		"""
		method deciding over which action to take
		"""

		if self.infile is None:
			# infile unset -> report top10
			self.report()

		elif self.infile:
			# infile set -> ingest
			self.ingest()

		# close sqlite connection
		self.conn.close()

	def report(self):
		"""
		report method
		:return: top10 score or domain specific data
		"""
		# if a specific domain is supplied return only that set
		if self.domain is not None:
			# first and last time seen spam from specified domain
			first = self.conn.execute("SELECT ts FROM spam WHERE domain=:domain ORDER BY ts LIMIT 1",
									  {"domain": self.domain}).fetchone()[0]
			last = self.conn.execute("SELECT ts FROM spam WHERE domain=:domain ORDER BY ts DESC LIMIT 1",
									 {"domain": self.domain}).fetchone()[0]

			print("First seen : {first}\nLast seen : {last}\n".format(first=first, last=last))

			result = self.conn.execute('SELECT COUNT(*) AS messages,COUNT(DISTINCT user) AS bots,domain FROM spam '
									   'WHERE domain=\'{}\';'.format(self.domain))
		else:

			result = self.conn.execute('SELECT COUNT(*) AS messages,COUNT(DISTINCT user) AS bots,domain AS domain '
									   'FROM spam GROUP BY domain ORDER BY 1 DESC LIMIT 10;')

		# format data as table
		table = tabulate.tabulate(result, headers=["messages", "bots", "domain"], tablefmt="orgtbl")
		print(table)



	def ingest(self):
		"""
		method to ingest xml messages into sqlite database
		"""
		try:
			with open(self.infile, "r", encoding="utf-8") as spam:
				log = re.findall(self.message_pattern, spam.read())

			self.db_import(log)
		except FileNotFoundError as err:
			print(err)
			exit(1)

	def db_import(self, message_log):
		"""
		import xml stanzas into database
		:param message_log: xml messages
		"""
		self.conn.execute('''CREATE TABLE IF NOT EXISTS "spam" ("user" TEXT, "domain" TEXT, "ts" TEXT, "message" TEXT, 
			PRIMARY KEY("domain","ts"));''')

		for message in message_log:
			message_parsed = ElementTree.fromstring(message)

			# parse from tag
			spam_from = message_parsed.get('from')
			match = self.jid_pattern.match(spam_from)
			(node, domain, resource) = match.groups()

			# stamp
			all_delay_tags = message_parsed.findall('.//{urn:xmpp:delay}delay')
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
				self.conn.execute('INSERT INTO spam  VALUES(:user, :domain, :spam_time, :spam_body);',
								  {"user": node, "domain": domain, "spam_time": spam_time, "spam_body": spam_body})
			except sqlite3.IntegrityError:
				pass
			finally:
				self.conn.commit()


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('-in', '--infile', help='set path to input file', dest='infile')
	parser.add_argument('-d', '--domain', help='specify report domain', dest='domain')
	args = parser.parse_args()

	# run
	AbuseReport(args).main()

"""
# Top 10 Domains and their score
SELECT COUNT(*) AS messages,COUNT(DISTINCT user) AS bots,domain AS 'domain'
FROM spam 
GROUP BY domain
ORDER BY 1 DESC LIMIT 10;

# Most frequent messages
SELECT COUNT(*) as count, COUNT(distinct user||domain) as bots,message
FROM spam
GROUP BY message HAVING bots > 1 
ORDER BY 1 DESC LIMIT 5;

# report sql
SELECT COUNT(*) AS messages,COUNT(DISTINCT user) AS bots,domain
FROM spam 
WHERE domain="default.rs";
"""
