# -*- coding: utf-8 -*-
import dns.resolver as dns
import tabulate


class ReportDomain:
	def __init__(self, config, conn):
		"""
		:param config: configuration object
		:param conn: sqlite connection object
		"""
		self.config = config
		self.conn = conn

	def report_template(self, template, domain, query):
		"""
		method to retrieve and format the template file
		:type template: str
		:type domain: str
		:type query: list
		:param template: string containing the abuse report template
		:param domain: string containing a domain name
		:param query: list of tuples containing the query results for the specified domain/s
		:return: string containing the fully formatted abuse report
		"""
		name = self.config.get_at("name")

		# lookup srv and domain info
		info = self.srvlookup(domain)
		srv = info[0]["host"]
		ips = "".join(info[0]["ip"])
		summary = tabulate.tabulate(query, headers=["messages", "bots", "domain", "first seen", "last seen"],
									tablefmt="orgtbl")

		report_out = template.format(name=name, domain=domain, srv=srv, ips=ips, summary=summary)

		return report_out

	def report_jids(self, domain):
		"""
		method to collect all involved jids from the database
		:type domain: str
		:param domain: string containing a domain name
		:return: formatted result string
		"""

		jids = self.conn.execute('''SELECT user || '@' || domain as jid FROM spam WHERE domain=:domain GROUP BY user
			ORDER BY 1;''', {"domain": domain}).fetchall()

		return tabulate.tabulate(jids, tablefmt="plain")

	def report_logs(self, domain):
		"""
		method to collect all messages grouped by frequency
		:type domain: str
		:param domain: string containing a domain name
		:return: formatted string containing the result
		"""
		logs = self.conn.execute('''SELECT CHAR(10) || MIN(ts) || ' - ' || MAX(ts) || char(10) || COUNT(*) || 
			'messages:' || char(10) ||'========================================================================' || 
			char(10) || message || char(10) || '========================================================================'
			FROM spam WHERE domain=:domain GROUP BY message ORDER BY COUNT(*) DESC LIMIT 10;''', {"domain": domain}).fetchall()

		return tabulate.tabulate(logs, tablefmt="plain")

	def srvlookup(self, domain):
		"""
		srv lookup method for the domain provided, if no srv record is found the base domain is used
		:type domain: str
		:param domain: provided domain to query srv records for
		:return: sorted list of dictionaries containing host and ip info
		"""
		# init result list
		results = list()

		try:
			srv_records = dns.query('_xmpp-client._tcp.{}'.format(domain), 'SRV')

		except (dns.NXDOMAIN, dns.NoAnswer):
			# catch NXDOMAIN and NoAnswer tracebacks
			srv_records = None

		# extract record
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
