# ejabberd mod_spam_filter ingest

## installation
Python 3 virtual environment
```bash
virtualenv -p python3
pip install -r requirements.txt
```

## configuration
### ejabberd
`/etc/ejabberd/modules.d/mod_spam_filter.yml`
```yaml
modules:
  mod_spam_filter:
    ...
    spam_dump_file: "/var/log/ejabberd/spam-@HOST@.txt"
    ...
```

## usage main.py
```
usage: main.py [-h] [-in INFILE [INFILE ...]] [-d DOMAIN] [-r]

optional arguments:
  -h, --help            show this help message and exit
  -in INFILE [INFILE ...], --infile INFILE [INFILE ...]
                        set path to input file
  -d DOMAIN, --domain DOMAIN
                        specify report domain
  -r, --report          toggle report output to file
```

#### -in / --infile
The `--in` or `--infile` argument is designed to run automatically via the logrotate daemon. Therefor the script is 
able to process gzip compressed files and also multiple files at once via shell expansion.

##### example
If ejabberd is configured to create multiple spamdump files it is possible to ingest all files at once, following 
this example.
```bash
$ ./main.py --in /var/log/ejabberd/spam-*.log
```

#### -d / --domain
If a domain is specifically defined to be processed, the script will only query the sqlite database for that domain. 
It is possible to provide multiple domains at once via multiple `-d` or `--domain` arguments.

##### example
```bash
$ ./main.py --d example.tld -d example.com

|   messages |   bots | domain      | first seen                  | last seen                   |
|------------+--------+-------------+-----------------------------+-----------------------------|
|         15 |      9 | example.tld | 2019-04-28T20:19:43.939926Z | 2019-05-22T13:59:53.339834Z |
|         23 |      7 | example.com | 2018-02-28T20:19:43.939926Z | 2019-05-22T13:59:53.339834Z |
```

#### -r / --report
This flag will only take effect if the `-d` or `--domain` argument is used. If that is the case, the script will 
automatically gather information about the specified domain and write them to the `report` directory.
