#!/usr/bin/env python3

import requests
import json

res_url = 'https://atlas.ripe.net/api/v2/measurements/%d/results/?format=json'
neither = json.loads(requests.get(res_url % 33172615).text)
eder    = json.loads(requests.get(res_url % 33173068).text)

baseline_probes = set([msm['prb_id'] for msm in eder])
baseline_resolvers = set()
eder_resolvers = set()

for msm in neither:
	if 'resultset' not in msm:
		continue
	prb_id = msm['prb_id']
	if prb_id not in baseline_probes:
		continue
	for rs in msm['resultset']:
		if 'result' not in rs \
		or rs['result']['ANCOUNT'] < 1:
			continue
		baseline_resolvers.add((prb_id, rs['dst_addr']))

for msm in eder:
	if 'resultset' not in msm:
		continue
	prb_id = msm['prb_id']
	for rs in msm['resultset']:
		if 'result' not in rs \
		or rs['result']['ANCOUNT'] < 1:
			continue
		eder_resolvers.add((prb_id, rs['dst_addr']))

print('# resolvers in both sets: %d' % len(baseline_resolvers & eder_resolvers))
print('# resolvers only in the neither set: %d' % len(baseline_resolvers - eder_resolvers))
print('# resolvers only in the eder set: %d' % len(eder_resolvers - baseline_resolvers))

