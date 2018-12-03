#!/usr/bin/env python3
from flask import Flask
from flask import request
import requests
import dns.query
import dns.zone
import dns.resolver
import time
import json


def get_A_addresses(rdataset, nodename, address_list):
    for rd in rdataset:
        if isinstance(rd, (dns.rdataset.Rdataset, list)):
            get_A_addresses(rd, nodename, address_list)
        elif isinstance(rd, dns.rdtypes.IN.A.A):
            address_list.append((nodename, rd.address))
        else:
            pass
    return

app = Flask(__name__)
@app.route('/metrics', methods=['GET', 'POST'])
def metrics_output():
    targets = []
    name_servers = []
    prometheus_job = 'dns_blackbox_icmp'
    file_prefix = 'dns_blackbox_icmp'
    domain_name = None
    if request.method == 'POST':
        domain_name = request.form.get('domain_name')
    else:
        domain_name = request.args.get('domain_name')
    if not domain_name:
        return('Missing parameter: domain_name')
    try:
        answers = dns.resolver.query(domain_name, 'NS')
    except:
        return('Error getting nameservers for domain: {}'.format(domain_name))
    xfer_success = None
    for ns in answers:
        try:
            startTime = time.time()
            z = dns.zone.from_xfr(dns.query.xfr(str(ns), domain_name))
            zoneorigin = str(z.origin)[:-1]
        except:
            name_servers.append((str(ns), None, None))
        else:
            name_servers.append((str(ns), z['@'].rdatasets[0].items[0].serial, time.time() - startTime))
            xfer_success = True
    if not xfer_success:
        return('Error while transfering zone {} from nameservers:\n'.format(domain_name),
               '\n'.join(list(map(lambda ns: ns[0], name_servers))))

    names = z.keys()
    for n in names:
        get_A_addresses(z[n].rdatasets, str(n), targets)
    hosts = []
    try:
        with open(''.join(['./', file_prefix,'_', str(z.origin), 'json']), 'w') as output_file:
            for target in targets:
                hosts.append(
                    {'labels': {'hostname': '.'.join([target[0], zoneorigin]), 'job': prometheus_job},
                     'targets': [target[1], ]})
            # print(json.dumps(hosts, sort_keys=True, indent=4))
            print(json.dumps(hosts, sort_keys=True, indent=4), file=output_file)
    except:
        return('Error while writing json file {} '.format(''.join(['./', file_prefix,'_', str(z.origin), 'json'])))
    metrics = []
    for ns in name_servers:
        nameserver = str(ns[0])[:-1]
        if ns[0] and ns[1]:
            metrics.append('zone_xfer_success {{job="dns_a_discover", name_server="{}", zone_origin="{}"}} 1'
                           .format(nameserver, zoneorigin ))
            metrics.append('zone_serial {{job="dns_a_discover", name_server="{}", zone_origin="{}"}} {}'
                           .format(nameserver, zoneorigin, ns[1]))
            metrics.append('zone_xfer_time {{job="dns_a_discover", name_server="{}", zone_origin="{}"}} {}'
                           .format(nameserver, zoneorigin, ns[2]))
        else:
            metrics.append('zone_xfer_success {{job="dns_a_discover", name_server="{}", zone_origin="{}"}} 0'
                           .format(nameserver, str(z.origin)[:-1]))
    return('\n'.join(metrics))