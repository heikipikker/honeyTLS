# honeyTLS

Nothing but a simple dirty bash script to set up Bro, JA3 script for Bro and Nginx, that can be used as a simple honeypot to capture JA3 hashes (SSL/TLS client fingerprints).


Alternatively, you can use [@Andrew___Morris](https://twitter.com/Andrew___Morris)'s one-liner to skim JA3 SSL fingerprints directly off the wire using tcpdump and some bash redirection:

`tcpdump -w - -s 0 -i en0 -n -U | python -u ja3.py -a -j /dev/stdin`


### Reference:
- [JA3](https://github.com/salesforce/ja3) - A method for profiling SSL/TLS Clients

### TODO:

- [x] Splunk to CSV script
- [ ] Enrich the collected data
    - [ ] [GreyNoise Intelligence API](https://github.com/GreyNoise-Intelligence/api.greynoise.io)
    - [ ] [Cymon API](http://docs.cymon.io/)
- [ ] Visualization script
- [ ] Complete the documentation and analysis report
