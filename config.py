# -*- coding: utf-8 -*-
import json
import os

# filepath of the config.json in the project directory
path = os.path.dirname(__file__)
filepath = ("/".join([path, "config.json"]))

# try to read config.json if nonexistent create config.json an populate it
try:
	with open(filepath, "r", encoding="utf-8") as f:
		config = json.load(f)

except FileNotFoundError:
	with open(filepath, "w", encoding="utf-8") as f:
		config = {
			"name": "",
		}
		f.write(json.dumps(config))


class Config(object):
	name = config["name"]
