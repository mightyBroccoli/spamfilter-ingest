# -*- coding: utf-8 -*-
import json
import os
import sys


class Config(object):
	def __init__(self):
		self.config = dict()

		# filepath of the config.json in the project directory
		self.path = os.path.dirname(__file__)
		self.filepath = ('/'.join([self.path, 'config.json']))

	def load(self):
		try:
			# try to read config.json
			with open(self.filepath, "r", encoding="utf-8") as f:
				self.config = json.load(f)

		except FileNotFoundError:
			# if file is absent create file
			open(self.filepath, "w").close()
			print("-- config.json is missing.", file=sys.stderr)
			print("-- {file} has been created.".format(file=self.filepath), file=sys.stderr)

		except json.decoder.JSONDecodeError:
			# config file is present but empty
			print("-- JSON parsing error, please check your config.json file.", file=sys.stderr)
			pass

		return self.config
