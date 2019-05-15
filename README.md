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
    spam_dump_file: "/var/log/ejabberd/spam-example.de.txt"
    ...
```

## usage main.py
```
usage: main.py [-h] [-in INFILE] [-d DOMAIN]

optional arguments:
  -h, --help            show this help message and exit
  -in INFILE, --infile INFILE
                        set path to input file
  -d DOMAIN, --domain DOMAIN
                        specify report domain
```

The `--in` argument does only support a single log file at a time.

## usage abusereport-domain.sh
```bash
./abusereport-domain.sh domain.tld
```