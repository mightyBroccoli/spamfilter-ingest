#!/bin/sh
#
# This script will generate an abuse report based on data stored in spam.db
# for a supplied XMPP domain.
#
# The report will contain:
#
#  - the abuse contact for the server IP
#  - a form letter with evidence
#  - an attachment with the bot JIDs
#  - an attachment with the top 10 most often message body values

domain=$1

[ -z "$domain" ] && {
	sqlite3 -column -header spam.db "SELECT COUNT(*) AS messages,COUNT(DISTINCT user) AS bots,domain AS 'domain' FROM spam GROUP BY domain ORDER BY 1 DESC LIMIT 10"
	return
}

date=$(date +%F)

srv=$( ( dig +short SRV "_xmpp-client._tcp.$domain" | grep . || echo "0 0 5222 $domain" ) | sort -n | sed -e 's/[[:digit:]]\+[[:space:]]\+//g' -e 's/\.$//')
ips=$domain
if [ "$srv" ] ; then
	# resolve the XMPP server, filter out host names (CNAMEs),
	# aggregate into one line
	ips=$(dig +short $srv | grep -v '\.$' | tr '\n' ' ')

	for ip in $ips ; do
		whois=$(whois -b $ip | grep -v '^%'|grep -v '^$')
		abuse=$(echo "$whois"|awk '/^abuse-mailbox:/ {print $2}')
	done
fi

SUBJECT="XMPP spam report for $domain / $ips"
SUMMARY=$(sqlite3 -column -header spam.db "SELECT COUNT(*) AS messages,COUNT(DISTINCT user) AS bots,domain FROM spam WHERE domain='$domain'")


cat <<EOF
$whois

Subject: $SUBJECT

XMPP domain: $domain
Server:      $srv
Jabber IP:   $ips

$SUMMARY

EOF

(
cat <<EOF
XMPP domain: $domain
Server:      $srv
Jabber IP:   $ips

Hi,

the above mentioned server is used as an open relay to send vast amounts
of XMPP spam to different unrelated servers, such as the server I
administer.

Spammers are using the In-Band-Registration feature on that server to
create a large number of accounts, and to send mass messages to my
users.

Please contact the server owner to disable In-Band-Registration, to take
measures against spam relaying or to shut down the XMPP service.

Also please find attached a list of the bot accounts and an excerpt of
the spam messages sent to my service.

$SUMMARY


Kind regards,

$NAME

EOF
) > abuse-$date-$domain.txt

LOGS=abuse-$date-$domain-logs.txt
JIDS=abuse-$date-$domain-JIDs.txt

sqlite3 spam.db "SELECT char(10)||MIN(ts)||' - '||MAX(ts)||char(10)||COUNT(*)||' messages:'||char(10)||'========================================================================'||char(10)||message||char(10)||'========================================================================' FROM spam WHERE domain='$domain' GROUP BY message ORDER BY COUNT(*) DESC LIMIT 10" > $LOGS

# first / last record
echo "first seen:" $(sqlite3 spam.db "SELECT ts FROM spam WHERE domain='$domain' ORDER BY ts LIMIT 1")
echo "last seen:" $(sqlite3 spam.db "SELECT ts FROM spam WHERE domain='$domain' ORDER BY ts DESC LIMIT 1")

# without number of messages
sqlite3 spam.db "SELECT user || '@' || domain as jid FROM spam WHERE domain='$domain' GROUP BY user ORDER BY 1" > $JIDS
# with number of messages
#sqlite3 spam.sqlite "SELECT COUNT(*),user || '@' || domain as jid FROM spam WHERE domain='$domain' GROUP BY user ORDER BY 2"

echo $LOGS
echo $JIDS
#cat abuse-$date-$domain.txt

#echo mutt $abuse -i abuse-$date-$domain.txt -s \"$SUBJECT\" -a $LOGS -a $JIDS
