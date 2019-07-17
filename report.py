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

	def template(self, template: str, domain: str, query: list):
		"""
		method to retrieve and format the template file
		:param template: string containing the abuse report template
		:param domain: string containing a domain name
		:param query: list of tuples containing the query results for the specified domain/s
		:return: string containing the fully formatted abuse report
		"""
		name = self.config.get_at("name")

		# lookup and format srv target and ip
		srv, ips = self.srv(domain)
		summary = tabulate.tabulate(query, headers=["messages", "bots", "domain", "first seen", "last seen"],
									tablefmt="github")

		report_out = template.format(name=name, domain=domain, srv=srv, ips=ips, summary=summary)

		return report_out

	def jids(self, domain: str):
		"""
		method to collect all involved jids from the database
		:param domain: string containing a domain name
		:return: formatted result string
		"""

		jids = self.conn.execute('''SELECT user || '@' || domain as jid FROM spam WHERE domain=:domain GROUP BY user
			ORDER BY 1;''', {"domain": domain}).fetchall()

		return tabulate.tabulate(jids, tablefmt="plain")

	def logs(self, domain: str):
		"""
		method to collect all messages grouped by frequency
		:param domain: string containing a domain name
		:return: formatted string containing the result
		"""
		logs = self.conn.execute('''SELECT CHAR(10) || MIN(ts) || ' - ' || MAX(ts) || char(10) || COUNT(*) || 
			'messages:' || char(10) ||'========================================================================' || 
			char(10) || message || char(10) || '========================================================================'
			FROM spam WHERE domain=:domain GROUP BY message ORDER BY COUNT(*) DESC LIMIT 10;''', {"domain": domain}).fetchall()

		return tabulate.tabulate(logs, tablefmt="plain")

	def srv(self, domain: str, only_highest: bool = True):
		info = self._srvlookup(domain)

		if only_highest:
			target = info[0]["host"]
			ips = info[0]["ip"]

			return target, ips

		return info

	@staticmethod
	def _getip(domain: str):
		"""
		method to query the a / aaaa record of a specified domain
		:param domain: valid domain target
		:return: filtered list of all a/ aaaa records
		"""
		# init records
		a, a4 = None, None

		try:
			# query and join both a and aaaa records
			a = ", ".join([ip.address for ip in dns.query(domain, "A")])
			a4 = ", ".join([ip.address for ip in dns.query(domain, "AAAA")])

		except (dns.NXDOMAIN, dns.NoAnswer):
			# catch NXDOMAIN and NoAnswer tracebacks not really important
			pass

		return list(filter(None.__ne__, [a, a4]))

	def _srvlookup(self, domain: str):
		"""
		srv lookup method for the domain provided, if no srv record is found the base domain is used
		:param domain: provided domain to query srv records for
		:return: sorted list of dictionaries containing host and ip info
		"""
		# init
		results = list()
		srv_records = None

		try:
			srv_records = dns.query('_xmpp-client._tcp.{}'.format(domain), 'SRV')

		except (dns.NXDOMAIN, dns.NoAnswer):
			# catch NXDOMAIN and NoAnswer tracebacks
			pass

		# extract record
		if srv_records is not None:
			# extract all available records
			for record in srv_records:
				info = dict()

				# gather necessary info from srv records
				info["host"] = record.target.to_text().rstrip('.')
				info["port"] = record.port
				info["weight"] = record.weight
				info["priority"] = record.priority
				info["ip"] = ", ".join(self._getip(record.target.to_text()))
				results.append(info)

			# return list sorted by priority and weightre
			return sorted(results, key=lambda i: (i['priority'], i["weight"]))

		# prevent empty info when srv records are not present
		info = dict()

		# gather necessary info from srv records
		info["host"] = domain
		info["ip"] = ", ".join(self._getip(domain))
		results.append(info)

		return results
