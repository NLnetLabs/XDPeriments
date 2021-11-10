#!/usr/bin/env python3

import requests
import json

res_url = 'https://atlas.ripe.net/api/v2/measurements/%d/results/?format=json'
eder    = json.loads(requests.get(res_url % 33267733).text)
neither = json.loads(requests.get(res_url % 33267734).text)

eder_probes = set([msm['prb_id'] for msm in eder])
eder_resolvers = set()
neither_probes = set([msm['prb_id'] for msm in neither])
neither_resolvers = set()

for msm in neither:
	if 'resultset' not in msm:
		continue
	prb_id = msm['prb_id']
	if prb_id not in eder_probes:
		continue
	for rs in msm['resultset']:
		if 'result' not in rs \
		or rs['result']['ANCOUNT'] < 1:
			continue
		neither_resolvers.add((prb_id, rs['dst_addr']))

for msm in eder:
	if 'resultset' not in msm:
		continue
	prb_id = msm['prb_id']
	if prb_id not in neither_probes:
		continue
	for rs in msm['resultset']:
		if 'result' not in rs \
		or rs['result']['ANCOUNT'] < 1:
			continue
		eder_resolvers.add((prb_id, rs['dst_addr']))

print('# probes participating: %d' % len(eder_probes & neither_probes))
print('# resolvers in both sets: %d' % len(eder_resolvers & neither_resolvers))
print('# resolvers only in the neither set: %d' % len(neither_resolvers - eder_resolvers))
print('# resolvers only in the eder set: %d' % len(eder_resolvers - neither_resolvers))

