#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import datetime as dt
import gzip
import os
import re
import sqlite3

import dns.resolver as dns
import tabulate
from defusedxml import ElementTree

from config import Config


class AbuseReport:
	"""Ingestation script for ejabberd spam logs"""

	def __init__(self, arguments):
		self.infile = arguments.infile
		self.domain = arguments.domain
		self.report = arguments.report
		self.path = os.path.dirname(__file__)

		self.conn = sqlite3.connect("/".join([self.path, "spam.db"]))
		self.jid_pattern = re.compile("^(?:([^\"&'/:<>@]{1,1023})@)?([^/@]{1,1023})(?:/(.{1,1023}))?$")
		self.message_pattern = re.compile(r'<message.*?</message>', re.DOTALL)

	def main(self):
		"""
		method deciding over which action to take
		"""
		if self.infile is None:
			# infile unset -> report top10
			self.egest()

		elif self.infile:
			# infile set -> ingest
			self.ingest()

		# close sqlite connection
		self.conn.close()

	def egest(self):
		"""
		report method
		:return: top10 score or domain specific data
		"""
		result = list()

		# if domain is specified return info for that domain
		if self.domain is not None:
			result = list()

			# iterate over all domains supplied
			for domain in self.domain:

				query = self.conn.execute('''SELECT COUNT(*) AS messages,COUNT(DISTINCT user) AS bots,domain,
					MIN(ts) AS first,MAX(ts) AS last FROM spam WHERE domain = :domain;''',
					{"domain": domain}).fetchall()

				# ugly tuple list swapping for nicer formatting
				temp = list(query[0])
				if temp[2] is None:
					temp[2] = domain
					query[0] = tuple(temp)

				# extend result table
				result.extend(query)

				# generate report if enabled
				if self.report:
					self.gen_report(domain, query)
		else:
			# in any other case return top 10
			result = self.conn.execute('''SELECT COUNT(*) AS messages,COUNT(DISTINCT user) AS bots,domain AS domain 
				FROM spam GROUP BY domain ORDER BY 1 DESC LIMIT 10;''')

		# format data as table
		table = tabulate.tabulate(result, headers=["messages", "bots", "domain","first seen", "last seen"],
								  tablefmt="orgtbl")
		print(table)

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
				print(err)

			# if magic number is present decompress and decode file
			if content.startswith(magic_number):
				content = gzip.decompress(content).decode("utf-8")
			# in any other case read file normally
			else:
				content = content.decode("utf-8")

			# automated run None catch
			if content is not None:
				self.parse(content)

	def parse(self, infile):
		"""
		method to parse xml messages
		:param infile: string containing xml stanzas
		"""
		log = re.findall(self.message_pattern, infile)

		if log is not None:
			self.db_import(log)

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

	def gen_report(self, domain, query):
		try:
			# open abuse report template file
			with open("/".join([self.path, "template/abuse-template.txt"]), "r", encoding="utf-8") as template:
				report_template = template.read()

		except FileNotFoundError as err:
			print(err)
			exit(1)

		# current date
		now = dt.datetime.strftime(dt.datetime.now(), "%Y-%m-%d")

		# output to report directory
		report_filename = "abuse-{domain}-{date}.txt".format(date=now, domain=domain)
		jids_filename = "abuse-{domain}-{date}-jids.txt".format(date=now, domain=domain)
		logs_filename = "abuse-{domain}-{date}-logs.txt".format(date=now, domain=domain)

		# write report files
		with open("/".join([self.path, "report", report_filename]), "w", encoding="utf-8") as report_out:
			content = self.report_template(report_template, domain, query)
			report_out.write(content)

		with open("/".join([self.path, "report", jids_filename]), "w", encoding="utf-8") as report_out:
			content = self.report_jids(domain)
			report_out.write(content)

		with open("/".join([self.path, "report", logs_filename]), "w", encoding="utf-8") as report_out:
			content = self.report_logs(domain)
			report_out.write(content)

	def report_template(self, template, domain, query):
		name = Config.name

		# lookup srv and domain info
		info = self.srvlookup(domain)
		srv = info[0]["host"]
		ips = "".join(info[0]["ip"])
		summary = tabulate.tabulate(query, headers=["messages", "bots", "domain","first seen", "last seen"],
									tablefmt="orgtbl")

		report_out= template.format(name=name, domain=domain, srv=srv, ips=ips, summary=summary)

		return report_out

	def report_jids(self, domain):

		jids = self.conn.execute('''SELECT user || '@' || domain as jid FROM spam WHERE domain=:domain GROUP BY user
			ORDER BY 1;''', {"domain": domain}).fetchall()

		return tabulate.tabulate(jids, tablefmt="plain")

	def report_logs(self, domain):
		"""

		:param domain:
		:return:
		"""
		logs = self.conn.execute('''SELECT char(10)||MIN(ts)||' - '||MAX(ts)||char(10)||COUNT(*)||' messages:'||char(10)
			||'========================================================================'||char(10)||message||char(10)||
			'========================================================================' FROM spam WHERE domain=:domain
			GROUP BY message ORDER BY COUNT(*) DESC LIMIT 10;''', {"domain": domain}).fetchall()

		return tabulate.tabulate(logs, tablefmt="plain")

	def srvlookup(self, domain):
		"""
		srv lookup method for the domain provided, if no srv record is found the base domain is used
		:type domain: str
		:param domain: provided domain to query srv records for
		:return: sorted list of dictionaries containing host and ip info
		"""
		# srv
		query = '_xmpp-client._tcp.{}'.format(domain)

		try:
			srv_records = dns.query(query, 'SRV')

		except (dns.NXDOMAIN, dns.NoAnswer):
			# catch NXDOMAIN and NoAnswer tracebacks
			srv_records = None

		# extract record
		results = list()

		if srv_records is not None:
			# extract all available records
			for record in srv_records:
				info = dict()

				# gather necessary info from srv records
				info["host"] = str(record.target).rstrip('.')
				info["weight"] = record.weight
				info["priority"] = record.priority
				info["ip"] = [ip.address for ip in dns.query(info["host"], "A")]
				results.append(info)

			# return list sorted by priority and weight
			return sorted(results, key=lambda i: (i['priority'], i["weight"]))

		# prevent empty info when srv records are not present
		info = dict()

		# gather necessary info from srv records
		info["host"] = domain
		info["ip"] = [ip.address for ip in dns.query(info["host"], "A")]
		results.append(info)

		return results


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('-in', '--infile', nargs='+', help='set path to input file', dest='infile')
	parser.add_argument('-d', '--domain', action='append', help='specify report domain', dest='domain')
	parser.add_argument('-r', '--report', action='store_true',  help='toggle report output to file', dest='report')
	args = parser.parse_args()

	# run
	AbuseReport(args).main()
