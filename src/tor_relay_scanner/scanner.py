#!/usr/bin/env python3

import asyncio
import random
import sys
import urllib.parse

import requests

TIMEOUT = 10.0


class TCPSocketConnectChecker:
    def __init__(self, host, port, timeout=TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connection_status = None

    def __repr__(self):
        return "{}:{}".format(
            self.host if self.host.find(":") == -1 else "[" + self.host + "]",
            self.port)

    async def connect(self):
        try:
            # Open connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), TIMEOUT)
            # And close it
            writer.close()
            await writer.wait_closed()
            self.connection_status = True
            return (True, None)
        except (OSError, asyncio.TimeoutError) as e:
            self.connection_status = False
            return (False, e)


class TorRelayGrabber:
    def _grab(self, url):
        with requests.get(url, timeout=int(TIMEOUT)) as r:
            return r.json()

    def grab(self):
        BASEURL = "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses"
        # Use public CORS proxy as a regular proxy in case if onionoo.torproject.org is unreachable
        URLS = (BASEURL,
                "https://corsbypasser.herokuapp.com/" + BASEURL,
                "https://corsanywhere.herokuapp.com/" + BASEURL,
                "https://tauron.herokuapp.com/" + BASEURL)

        for url in URLS:
            try:
                return self._grab(url)
            except Exception as e:
                print("Can't download Tor Relay data from/via {}: {}".format(
                    urllib.parse.urlparse(url).hostname, e
                ), file=sys.stderr)

    def grab_parse(self):
        return self.grab()["relays"]


class TorRelay:
    def __init__(self, relayinfo):
        self.relayinfo = relayinfo
        self.fingerprint = relayinfo["fingerprint"]
        self.iptuples = self._parse_or_addresses(relayinfo["or_addresses"])
        self.reachable = list()

    def _reachable(self):
        r = ""
        for i in self.reachable:
            if r:
                r += "\n"
            r += "{}:{} {}".format(i[0] if i[0].find(":") == -1 else "[" + i[0] + "]",
                                   i[1],
                                   self.fingerprint,)

        return r

    def __repr__(self):
        if not self.reachable:
            return str(self.relayinfo)
        return self._reachable()

    def __len__(self):
        return len(self.reachable)

    def _parse_or_addresses(self, or_addresses):
        ret = list()
        for address in or_addresses:
            parsed = urllib.parse.urlparse("//" + address)
            ret.append((parsed.hostname, parsed.port))
        return ret

    async def check(self):
        for i in self.iptuples:
            s = TCPSocketConnectChecker(i[0], i[1])
            sc = await s.connect()
            if sc[0]:
                self.reachable.append(i)

        return bool(self.reachable)


async def main_async():
    NUM_RELAYS = 30
    WORKING_RELAY_NUM_GOAL = 5

    print(f"Tor Relay Scanner. Will scan up to {WORKING_RELAY_NUM_GOAL}" +
          " working relays (or till the end)", file=sys.stderr)
    print("Downloading Tor Relay information from onionoo.torproject.org…", file=sys.stderr)
    relays = TorRelayGrabber().grab_parse()
    print("Done!", file=sys.stderr)

    random.shuffle(relays)
    working_relays = list()
    ntry = 0
    relaypos = 0
    numtries = round(len(relays) / NUM_RELAYS)
    for ntry in range(numtries):
        if len(working_relays) >= WORKING_RELAY_NUM_GOAL:
            break

        relaynum = min(NUM_RELAYS, len(relays) - relaypos - 1)
        test_relays = [TorRelay(relays[x])
                       for x in range(relaypos, relaypos+relaynum)]
        relaypos += NUM_RELAYS

        if not test_relays:
            break

        print(
            f"\nTry {ntry}/{numtries}, We'll test the following {NUM_RELAYS} random relays:", file=sys.stderr)
        for relay in test_relays:
            print(relay, file=sys.stderr)
        print("", file=sys.stderr)

        print(f"Already found {len(working_relays)} good relays. Test started…", file=sys.stderr)
        tasks = list()
        for relay in test_relays:
            tasks.append(asyncio.create_task(relay.check()))
        fin = await asyncio.gather(*tasks)
        print("", file=sys.stderr)

        print("The following relays are reachable this try:", file=sys.stderr)
        for relay in test_relays:
            if relay:
                print(relay)
                working_relays.append(relay)
        if not any(test_relays):
            print("No relays are reachable this try.", file=sys.stderr)

    if ntry > 1:
        print("", file=sys.stderr)
        print("All reachable relays:", file=sys.stderr)
        for relay in working_relays:
            if relay:
                print(relay, file=sys.stderr)
        if not any(test_relays):
            print("No relays are reachable, at all.", file=sys.stderr)


def main():
    asyncio.run(main_async())
