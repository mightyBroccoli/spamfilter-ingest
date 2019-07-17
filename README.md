# ejabberd mod_spam_filter ingest
[![CodeFactor](https://www.codefactor.io/repository/github/mightybroccoli/spamfilter-ingest/badge)](https://www.codefactor.io/repository/github/mightybroccoli/spamfilter-ingest)

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

### config.json
The `config.json` file is used to preserve date from possible updates to this script. `config.py` will load `config
.json` to extract the name, which is used to sign the report message with. In the future there might be other things 
the `config.json` may contain.

```json
$ cat config.json
{
  "name": "username"
}
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

#### run with no argument
If `main.py` is run without any arguments attached, then the script will output a "top 10" table showing the amount 
of messages/ bots for the most spammy domains in the database.

##### example
```bash
$./main.py

|   messages |   bots | domain        |
|------------+--------+---------------|
|         42 |      1 | example.net   |
|         17 |      9 | example.rs    |
|          7 |      5 | example.cd    |
|          5 |      3 | example.de    |
|          4 |      4 | example.ru    |
|          3 |      1 | example.co.uk |
|          3 |      3 | example.com   |
|          3 |      1 | example.net   |
|          3 |      1 | example.fr    |
|          3 |      1 | example.com   |
```

#### -in / --infile
The `--in` or `--infile` argument is designed to run automatically via the logrotate daemon. Therefore the script is 
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
