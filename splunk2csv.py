#!/usr/bin/env python

import sys
import urllib
import httplib2
import time
import re
from time import localtime,strftime
from xml.dom import minidom
import json
import argparse

baseurl = 'https://splunkserver-nginx-rev-proxy:8888'
nginxuser = 'user'
nginxpass = 'pass'
exportfile = 'honeytls-data.csv'
enrichdata = True

searchquery = '''index=main source=/opt/bro/logs/current/ssl.log ja3=* earliest=-24h | 
 rename id.orig_h AS IPSource id.resp_h AS IPDestination id.orig_p AS PortSource id.resp_p
 AS PortDestination | join IPSource  host PortDestination type=left [search index=main 
 sourcetype="nginx_access" | rename ServerPort AS PortDestination] | table _time IPSource
 ja3 PortDestination PortSource server_name UserAgent Request'''


ASCII = r"""
#######################################################
       __                          ________   _____
      / /_  ____  ____  ___  __  _/_  __/ /  / ___/
     / __ \/ __ \/ __ \/ _ \/ / / // / / /   \__ \ 
    / / / / /_/ / / / /  __/ /_/ // / / /______/ / 
   /_/ /_/\____/_/ /_/\___/\__, //_/ /_____/____/  
                        /____/                   
  splunk2csv | export and enrich the data from splunk
         a part of honeyTLS project by 0x4D31

#######################################################"""


def prepare_search(squery):
	# Remove leading and trailing whitespace from the search
	squery = squery.strip()
	# If the query doesn't already start with the 'search' operator or another 
	# generating command (e.g. "| inputcsv"), then prepend "search " to it.
	if not (squery.startswith('search') or squery.startswith("|")):
	    squery = 'search ' + squery
	return squery


def print_results(sq, bu, username, password):
	"""Get and print the search results"""
	myhttp = httplib2.Http(disable_ssl_certificate_validation=True)
	myhttp.add_credentials(username, password)
	# Create a search job
	resp, content = myhttp.request(bu + '/services/search/jobs','POST',
		body=urllib.urlencode({'search': sq}))
	if resp.status == 200 or resp.status == 201 or resp.status == 202:
	    sid = minidom.parseString(content).getElementsByTagName('sid')[0].childNodes[0].nodeValue
	    print("[+] Search job created, sid: {}".format(sid))
	else:
		print("\nHTTP Response Code: {}\nResponse Message: {}".format(resp.status, content))
		sys.exit()
	# Get the search status
	servicessearchstatusstr = '/services/search/jobs/%s/' % sid
	isnotdone = True
	while isnotdone:
	    searchstatus = myhttp.request(bu + servicessearchstatusstr, 'GET')[1]
	    isdonestatus = re.compile('isDone">(0|1)')
	    isdonestatus = isdonestatus.search(searchstatus).groups()[0]
	    if (isdonestatus == '1'):
	        isnotdone = False
	print("[+] Search is done, status: {}".format(isdonestatus))
	# Print the search results
	search_results_str = '/services/search/jobs/%s/results?output_mode=csv' % sid
	searchresults = myhttp.request(bu + search_results_str, 'GET')[1]
	print("[+] Search results:\n{}".format(searchresults))


def export_results(sq, bu, username, password, filename):
	"""Export the search results into a CSV file"""
	myhttp = httplib2.Http(disable_ssl_certificate_validation=True)
	myhttp.add_credentials(username, password)
	# Export the search result (csv)
	search_export_str = '/services/search/jobs/export?output_mode=csv'
	resp, content = myhttp.request(bu + search_export_str, 'POST',
		body=urllib.urlencode({'search': sq}))
	if resp.status == 200 or resp.status == 201 or resp.status == 202:
		# Write the results to a file
		with open(filename, 'w') as f:
		    f.write(content)
		print("[+] Search results exported to {}".format(filename))
	else:
		print("\nHTTP Response Code: {}\nResponse Message: {}".format(resp.status, content))
		sys.exit()


def parse_cmd_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-b', '--base-url',
        type=str,
        default=baseurl
    )
    parser.add_argument(
        '-u', '--user',
        type=str,
        default=nginxuser
    )
    parser.add_argument(
        '-p', '--passwd',
        type=str,
        default=nginxpass
    )
    parser.add_argument(
        '-o', '--output-file',
        type=str,
        default=exportfile
    )
    parser.add_argument(
        '-s', '--search-query',
        type=str,
        default=searchquery,
        help="Return the results in a table and include the 'IPSource'"
    )
    parser.add_argument(
        '-a', '--action',
        type=str,
        default="print",
        choices=["print", "export"]
    )
    parser.add_argument(
        '-e', '--enrich-data',
        action='store_true'
    )
    parser.set_defaults(enrich_data=enrichdata)
    parser.add_argument(
        '-eS', '--enrich-source',
        type=str,
        default="greynoise",
        choices=["greynoise", "cymon", "all"]
    )
    return parser.parse_args()


def main():
    args = parse_cmd_line_args()
    sq = prepare_search(squery=args.search_query)
    if args.action == "print":
    	print_results(
    		sq,
    		bu=args.base_url,
    		username=args.user,
    		password=args.passwd
    	)
    elif args.action == "export":
    	export_results(
    		sq,
    		bu=args.base_url,
    		username=args.user,
    		password=args.passwd,
    		filename=args.output_file
    	)


if __name__ == '__main__':
    print(ASCII)
    main()
