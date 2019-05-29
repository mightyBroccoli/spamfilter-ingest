# -*- coding: utf-8 -*-
import json

# try to read config.json if nonexistent create config.json an populate it
try:
	with open("config.json", "r", encoding="utf-8") as f:
		config = json.load(f)

except FileNotFoundError:
	with open("config.json", "w", encoding="utf-8") as f:
		config = {
			"name": "",
		}
		f.write(json.dumps(config))


class Config(object):
	"""extract secret key to use for the webserver"""
	name = config["name"]
