#!/usr/bin/env python3
from flask import Flask
from flask import request
import dns.query  # dnspython module
import dns.zone
import dns.resolver
import time
import json


prometheus_job = 'dns_blackbox_icmp'
file_prefix    = 'dns_blackbox_icmp'
txt_off        = 'no-dns-check'

def get_A_addresses(rdataset, nodename, records):
    for rd in rdataset:
        if isinstance(rd, (dns.rdataset.Rdataset, list)):
            print('RC {}'.format(rd))
            print(type(rd), 'RC')
            get_A_addresses(rd, nodename, records)
        elif isinstance(rd, dns.rdtypes.IN.A.A):
            print('Appending', rd.address)
            records.append((nodename, rd.address, 'A')) 
        elif isinstance(rd, dns.rdtypes.ANY.TXT.TXT):
            print('TXT', rd.strings[0].decode('UTF-8'))
            records.append((nodename, rd.strings[0].decode('UTF-8'), 'TXT'))     
        else:
            pass
    return
#def get_TXT_records(rdataset, nodename, address_list):
#    for rd in

app = Flask(__name__)
@app.route('/metrics', methods=['GET', 'POST'])
def metrics_output():
    targets = {}
    name_servers = []
    records = []
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
        return('Error while transfering zone {} from nameservers:\n{}'.format(domain_name,
               '\n'.join(list(map(lambda ns: ns[0], name_servers)))))
    names = z.keys()
    for n in names:
        get_A_addresses(z[n].rdatasets, str(n), records)
    txt_off_names = set([ record[0] for record in records if record[1] == txt_off ])
    targets = [record for record in records if (record[0] not in txt_off_names) and record[2] == 'A']
    hosts = []
    try:
        with open(''.join(['./', file_prefix,'_', str(z.origin), 'json']), 'w') as output_file:
            for target in targets:
                hosts.append(
                    {'labels': {'hostname': '.'.join([target[0], zoneorigin]), 'job': prometheus_job},
                     'targets': [target[1], ]})
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