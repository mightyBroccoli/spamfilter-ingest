#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import datetime as dt
import gzip
import os
import re
import sqlite3
import sys

import tabulate
from defusedxml import ElementTree

from config import Config
from report import ReportDomain


class AbuseReport:
	"""ingestion script for ejabberd spam logs"""

	def __init__(self, arguments):
		self.infile = arguments.infile
		self.domain = arguments.domain
		self.report = arguments.report
		self.start = arguments.start
		self.stop = arguments.stop or "now"
		self.path = os.path.dirname(__file__)
		self.config = Config()

		self.conn = sqlite3.connect("/".join([self.path, "spam.db"]))
		self.jid_pattern = re.compile("^(?:([^\"&'/:<>@]{1,1023})@)?([^/@]{1,1023})(?:/(.{1,1023}))?$")
		self.message_pattern = re.compile(r'<message.*?</message>', re.DOTALL)

	def main(self):
		"""main method guiding the actions to take"""
		# run check method before each execution
		self.check()

		if self.infile is None:
			# infile unset -> report top10
			self.egest()

		elif self.infile:
			# infile set -> ingest
			self.ingest()

		# close sqlite connection
		self.conn.close()

	def check(self):
		# check if the minimum requirements are met
		table = ('table', 'spam')
		master = self.conn.execute('''SELECT type, name from  sqlite_master;''').fetchall()

		# if not run create method
		if table not in master:
			self.create()

	def create(self):
		# open and execute base schema file
		script = "/".join([self.path, "schema.sql"])
		with open(script) as file:
			schema = file.read()

		self.conn.executescript(schema)

	def egest(self):
		"""egest method returning the database results"""
		# init result list
		result = list()

		# building block base query
		base_query = '''SELECT COUNT(*) AS messages,COUNT(DISTINCT user) AS bots,domain, MIN(ts) AS first, \
			MAX(ts) AS last FROM spam'''

		# date -Ins outputs %S,%f but python sqlite3 is not able to handle the ,
		if None not in (self.start, self.stop):
			self.start = self.start.replace(',', '.')
			self.stop = self.stop.replace(',', '.')

		# if a then from a up until end
		if self.start is not None:
			# correct timestamp for the local time zone
			timesperiod = '''ts > STRFTIME('%Y-%m-%dT%H:%M:%S', '{a}', 'localtime') \
				AND ts < STRFTIME('%Y-%m-%dT%H:%M:%S', '{b}', 'localtime')'''.format(a=self.start, b=self.stop)
		else:
			# default: query 1 month
			timesperiod = '''ts > DATETIME('now','start of day', '-1 months') \
				AND ts < STRFTIME('%Y-%m-%dT%H:%M:%S', 'now', 'localtime')'''

		# if one or more domains are specified return only their info
		if self.domain is not None:

			# iterate over all domains supplied
			for domain in self.domain:

				# build and execute
				sql = '''{base} WHERE domain = :domain AND {time};'''.format(base=base_query, time=timesperiod)
				query = self.conn.execute(sql, {"domain": domain}).fetchall()

				# if specified domain is not listed yet, the resulting table will not show the domain name
				# this ugly tuple 2 list swap prevents this
				temp = list(query[0])
				if temp[2] is None:
					temp[2] = domain
					query[0] = tuple(temp)

				# extend result tables
				result.extend(query)

				# generate report if enabled
				if self.report:
					self.gen_report(domain, query)

		else:
			# build and execute
			sql = '''SELECT COUNT(*) AS messages, COUNT(DISTINCT user) AS bots, domain AS \
				domain from spam WHERE {time} GROUP BY domain ORDER BY 1 DESC LIMIT 10;'''.format(time=timesperiod)
			result = self.conn.execute(sql).fetchall()

		# tabelize data
		spam_table = tabulate.tabulate(result, headers=["messages", "bots", "domain", "first seen", "last seen"],
									   tablefmt="github")

		# output to stdout
		output = "\n\n".join([spam_table])
		print(output, file=sys.stdout)

	def ingest(self):
		"""
		ingest method to split up the ingest file list
		if necessary decompression and decoding are applied
		"""
		magic_number = b"\x1f\x8b\x08"

		# iterate over all infile elements
		for element in self.infile:

			try:
				# open file in binary mode
				with open(element, "rb") as infile:
					content = infile.read()

			except FileNotFoundError as err:
				content = ""
				print(err, file=sys.stderr)

			# if magic number is present decompress and decode file
			if content.startswith(magic_number):
				content = gzip.decompress(content).decode("utf-8")
			# in any other case read file normally
			else:
				content = content.decode("utf-8")

			# automated run None catch
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

	def gen_report(self, domain: str, query: list):
		"""
		method generating the report files
		:param domain: string containing a domain name
		:param query: list of tuples containing the query results for the specified domain/s
		"""
		# init report class
		report = ReportDomain(self.config, self.conn)

		try:
			# open abuse report template file
			with open("/".join([self.path, "template/abuse-template.txt"]), "r", encoding="utf-8") as template:
				report_template = template.read()

		except FileNotFoundError as err:
			print(err, file=sys.stderr)
			exit(1)

		# current date
		now = dt.datetime.strftime(dt.datetime.now(), "%Y-%m-%d")

		# output to report directory
		report_filename = "abuse-{domain}-{date}.txt".format(date=now, domain=domain)
		jids_filename = "abuse-{domain}-{date}-jids.txt".format(date=now, domain=domain)
		logs_filename = "abuse-{domain}-{date}-logs.txt".format(date=now, domain=domain)

		# write report files
		with open("/".join([self.path, "report", report_filename]), "w", encoding="utf-8") as report_out:
			content = report.template(report_template, domain, query)
			report_out.write(content)

		with open("/".join([self.path, "report", jids_filename]), "w", encoding="utf-8") as report_out:
			content = report.jids(domain)
			report_out.write(content)

		with open("/".join([self.path, "report", logs_filename]), "w", encoding="utf-8") as report_out:
			content = report.logs(domain)
			report_out.write(content)


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('-in', '--infile', nargs='+', help='set path to input file', dest='infile')
	parser.add_argument('-d', '--domain', action='append', help='specify report domain', dest='domain')
	parser.add_argument('-r', '--report', action='store_true', help='toggle report output to file', dest='report')
	parser.add_argument('-f', '--from', help='ISO-8601 timestamp from where to search', dest='start')
	parser.add_argument('-t', '--to', help='ISO-8601 timestamp up until where to search', dest='stop')
	args = parser.parse_args()

	# run
	AbuseReport(args).main()
