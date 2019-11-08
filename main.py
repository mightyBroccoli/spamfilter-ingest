#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import datetime as dt
import os
import sqlite3
import sys

import tabulate

from ingest import IngestLogfile
from report import ReportDomain


class AbuseReport:
	"""ingestion script for ejabberd spam logs"""

	def __init__(self, arguments):
		self.infile = arguments.infile
		self.domain = arguments.domain
		self.report = arguments.report
		self.start = arguments.start
		self.stop = arguments.stop
		self.path = os.path.dirname(__file__)

        self.conn = sqlite3.connect("/".join([self.path, "spam.db"]))
        self.Report = ReportDomain(self.conn)
        self.Ingest = IngestLogfile(self.conn)

    def main(self):
        """main method guiding the actions to take"""
		# run check method before each execution
		self.check()

		if self.infile is None:
			# infile unset -> report top10
			self.egest()

        elif self.infile:
            # infile set -> ingest
            self.Ingest.read(self.infile)

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

		# parse time values
		if self.start is None:
			# default timeperiod are 31 days calculated via the timedelta
			default = dt.datetime.combine(dt.date.today(), dt.time()) - dt.timedelta(days=31)
			self.start = dt.datetime.strftime(default, "%Y-%m-%dT%H:%M:%S")

		if self.stop is None:
			# set stop value to now
			self.stop = dt.datetime.strftime(dt.datetime.now(), '%Y-%m-%dT%H:%M:%S')

		# add validated timestamps to report class
		self.Report.addtime(self.start, self.stop)

		# if one or more domains are specified return only their info
		if self.domain is not None:

			# iterate over all domains supplied
			for domain in self.domain:

				# build and execute
				sql = '''SELECT COUNT(*) AS messages, COUNT(DISTINCT user) AS bots, domain, MIN(ts) AS first, MAX(ts) AS last
					FROM spam
					WHERE domain = :domain
					AND ts > :start AND ts < :stop;'''
				parameter = {
					"domain": domain,
					"start": self.start,
					"stop": self.stop
				}
				query = self.conn.execute(sql, parameter).fetchall()

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
			sql = '''SELECT COUNT(*) AS messages, COUNT(DISTINCT user) AS bots, domain AS domain from spam
				WHERE ts > :start AND ts < :stop
			GROUP BY domain ORDER BY 1 DESC LIMIT 10;'''
			result = self.conn.execute(sql, {"start": self.start, "stop": self.stop}).fetchall()

        # tabelize data
        spam_table = tabulate.tabulate(result, tablefmt="psql", headers=["messages", "bots", "domain","first seen",
                                                                           "last seen"])

        # output to stdout
		output = "\n\n".join([spam_table])
        print(output, file=sys.stdout)

    def gen_report(self, domain: str, query: list):
        """
        method generating the report files
		:param domain: string containing a domain name
		:param query: list of tuples containing the query results for the specified domain/s
		"""
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
			content = self.Report.template(report_template, domain, query)
			report_out.write(content)

		with open("/".join([self.path, "report", jids_filename]), "w", encoding="utf-8") as report_out:
			content = self.Report.jids(domain)
			report_out.write(content)

		with open("/".join([self.path, "report", logs_filename]), "w", encoding="utf-8") as report_out:
			content = self.Report.logs(domain)
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
