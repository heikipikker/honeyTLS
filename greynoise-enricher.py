#!/usr/bin/env python

import requests
import json
import argparse
import datetime
import dateutil.parser
import csv
import socket

base_url = 'http://api.greynoise.io:8888/v1/'
path = 'query/ip'
exportfile = 'greynoise-output.csv'
max_last_seen = 7
row_number = 1


ASCII = r"""
#######################################################
       __                          ________   _____
      / /_  ____  ____  ___  __  _/_  __/ /  / ___/
     / __ \/ __ \/ __ \/ _ \/ / / // / / /   \__ \ 
    / / / / /_/ / / / /  __/ /_/ // / / /______/ / 
   /_/ /_/\____/_/ /_/\___/\__, //_/ /_____/____/  
                        /____/                   
 greynoise-enricher | enrich the data w/ Greynoise API
         a part of honeyTLS project by 0x4D31

#######################################################"""


def greynoise_request(ip):
    headers = {'User-Agent': "GreyNoise-Enricher"}
    req = requests.post(
        base_url + path,
        headers=headers,
        data={'ip': ip}
    )

    if req.status_code == 200:
        if req.json()["status"] in ["ok", "exists"]:
            return req.json()
        else:
            if req.json()["status"] == "unknown":
                print("No results for this query")
                return False
            else:
                print("Invalid status: {}".format(req.json()["status"]))
                return False
    else:
        print("Invalid HTTP return code {}".format(req.status_code))
        return False


def parse_cmd_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-ip', '--ip-address',
        type=str
    )
    parser.add_argument(
        '-a', '--action',
        type=str,
        default="print",
        choices=["rawprint", "print", "export"]
    )
    parser.add_argument(
        '-i', '--input-file',
        type=str
    )
    parser.add_argument(
        '-o', '--output-file',
        type=str,
        default=exportfile
    )
    parser.add_argument(
        '-m', '--max-lastseen',
        type=int,
        default=max_last_seen,
        help="Max last seen date in days, e.g. '7'"
    )
    return parser.parse_args()


def validate_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False


def main():
    args = parse_cmd_line_args()
    # Raw Print
    if args.action == "rawprint":
        data = greynoise_request(args.ip_address)
        if data:
            print(json.dumps(data, indent=4, separators=(',', ': ')))
    # Print
    elif args.action == "print":
        data = greynoise_request(args.ip_address)
        if data:
            metadata=data["records"][0]["metadata"]
            print("IP Address: {}".format(args.ip_address))
            for r in data["records"]:
                last_seen = dateutil.parser.parse(r["last_updated"])
                tz_info = last_seen.tzinfo
                xdaysago = datetime.datetime.now(tz_info) - datetime.timedelta(days=args.max_lastseen)
                if last_seen > xdaysago:
                    category=r["category"]
                    name=r["name"]
                    print("\t{}: {}".format(category, name))
            
            print("\tMetadata:\n\
                datacenter: {}\n\
                rdns: {}\n\
                rdns_parent: {}\n\
                org: {}\n\
                asn: {}\n\
                os: {}\n\
                tor: {}\n".format(
                    metadata["datacenter"],
                    metadata["rdns"],
                    metadata["rdns_parent"],
                    metadata["org"],
                    metadata["asn"],
                    metadata["os"],
                    metadata["tor"]
                )
            )
    # Export
    elif args.action == "export":
        if args.input_file:
            output_dict = {}
            csvReader = csv.reader(open(args.input_file, 'r'))
            for i in csvReader:
                activity = set()
                search_engine = set()
                worm = set()
                tool = set()
                actor = set()
                hosting = set()
                scanner = set()
                metadata = {}
                ip = i[row_number]
                if validate_ip(ip):
                    if ip not in output_dict:
                        print("- IP address: {}".format(ip))
                        output_dict[ip] = greynoise_request(ip)
                    if output_dict[ip]:
                        metadata = output_dict[ip]["records"][0]["metadata"]
                        for r in output_dict[ip]["records"]:
                            last_seen = dateutil.parser.parse(r["last_updated"])
                            tz_info = last_seen.tzinfo
                            xdaysago = datetime.datetime.now(tz_info) - datetime.timedelta(days=args.max_lastseen)
                            if last_seen > xdaysago:
                                if r["category"] == "activity":
                                    activity.add(r["name"])
                                elif r["category"] == "search_engine":
                                    search_engine.add(r["name"])
                                elif r["category"] == "worm":
                                    worm.add(r["name"])
                                elif r["category"] == "tool":
                                    tool.add(r["name"])
                                elif r["category"] == "actor":
                                    actor.add(r["name"])
                                elif r["category"] == "hosting":
                                    hosting.add(r["name"])
                                elif r["category"] == "scanner":
                                    scanner.add(r["name"])
                entry = [','.join(str(x) for x in activity),
                    ','.join(str(x) for x in search_engine),
                    ','.join(str(x) for x in worm),
                    ','.join(str(x) for x in tool),
                    ','.join(str(x) for x in actor),
                    ','.join(str(x) for x in hosting),
                    ','.join(str(x) for x in scanner),
                    metadata.get("datacenter", ''),
                    metadata.get("rdns", ''),
                    metadata.get("rdns_parent", ''),
                    metadata.get("org", ''),
                    metadata.get("asn", ''),
                    metadata.get("os", ''),
                    metadata.get("tor", '')]
                i += entry
                with open(args.output_file, 'a') as f:
                    csvWriter = csv.writer(f)
                    csvWriter.writerow(i)
        else:
            print("Error: No input file!")


if __name__ == '__main__':
    print("{}\n".format(ASCII))
    main()