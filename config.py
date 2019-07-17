# -*- coding: utf-8 -*-
import json
import os


class Config(object):
	def __init__(self):
		self.config = dict()
		self.valid_config = bool

		# filepath of the config.json in the project directory
		self.path = os.path.dirname(__file__)
		self.filepath = ('/'.join([self.path, 'config.json']))

		# load config
		self.load()

	def load(self):
		try:
			# try to read config.json
			with open(self.filepath, "r", encoding="utf-8") as f:
				self.config = json.load(f)

		except FileNotFoundError:
			# if file is absent create file
			open(self.filepath, "w").close()

		except json.decoder.JSONDecodeError:
			# config file is present but empty
			pass

	def get_at(self, attrib: str):
		"""
		retrieve attribute from config file
		:param attrib: keyword corresponding to keyword in config dictionary
		:return: value of specified keyword or False if keyword is not present in dictionary
		"""
		if attrib in self.config:
			# return corresponding attrib from config
			return self.config[attrib]
		else:
			# if attrib is not present in config return False
			self.config[attrib] = False

	def set_at(self, attrib: str, param):
		"""
		set attribute to parameter inside config file
		:param attrib: keyword which should be updated/created in config dictionary
		:param param: parameter the keyword should be updated to
		"""
		self.config[attrib] = param

		# save new attrib to file
		with open(self.filepath, "w", encoding="utf-8") as f:
			f.write(json.dumps(self.config, indent=4))

	def unset_at(self, attrib: str):
		"""
		unset attribute inside config file
		:param attrib: attribute which should be unset inside config file
		"""
		if attrib in self.config:
			# only if attrib is actually present unset it
			self.config.pop(attrib)
