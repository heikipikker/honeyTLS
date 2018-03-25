#!/usr/bin/env python

import urllib
import httplib2
import time
import re
from time import localtime,strftime
from xml.dom import minidom
import json

baseurl = 'https://splunkserver-nginx-rev-proxy:8888'
nginxuser = 'user'
nginxpass = 'pass'
exportfile = 'honeytls-data.csv'

searchquery = '''index=main source=/opt/bro/logs/current/ssl.log ja3=* earliest=-24h | 
 rename id.orig_h AS IPSource id.resp_h AS IPDestination id.orig_p AS PortSource id.resp_p
 AS PortDestination | join IPSource  host PortDestination type=left [search index=main 
 sourcetype="nginx_access" | rename ServerPort AS PortDestination]  |  table _time IPSource
 ja3 PortDestination PortSource server_name UserAgent Request'''

myhttp = httplib2.Http(disable_ssl_certificate_validation=True)
myhttp.add_credentials(nginxuser, nginxpass)

# Remove leading and trailing whitespace from the search
searchquery = searchquery.strip()

# If the query doesn't already start with the 'search' operator or another 
# generating command (e.g. "| inputcsv"), then prepend "search " to it.
if not (searchquery.startswith('search') or searchquery.startswith("|")):
    searchquery = 'search ' + searchquery

# Create a search job
searchjob = myhttp.request(baseurl + '/services/search/jobs','POST'
    ,body=urllib.urlencode({'search': searchquery}))[1]
sid = minidom.parseString(searchjob).getElementsByTagName('sid')[0].childNodes[0].nodeValue
print("[+] Search job created, sid: {}".format(sid))

# Get the search status
servicessearchstatusstr = '/services/search/jobs/%s/' % sid
isnotdone = True
while isnotdone:
    searchstatus = myhttp.request(baseurl + servicessearchstatusstr, 'GET')[1]
    isdonestatus = re.compile('isDone">(0|1)')
    isdonestatus = isdonestatus.search(searchstatus).groups()[0]
    if (isdonestatus == '1'):
        isnotdone = False
print("[+] Search is done, status: {}".format(isdonestatus))

# Print the search results

search_results_str = '/services/search/jobs/%s/results?output_mode=csv' % sid
searchresults = myhttp.request(baseurl + search_results_str, 'GET')[1]
print("[+] Search results:\n{}".format(searchresults))

# Export the search result (csv)

search_export_str = '/services/search/jobs/export?output_mode=csv'
searchresults = myhttp.request(baseurl + search_export_str, 'POST'
    , body=urllib.urlencode({'search': searchquery}))[1]

with open(exportfile, 'w') as f:
    f.write(searchresults)

print("[+] Search results exported to {}".format(exportfile))
