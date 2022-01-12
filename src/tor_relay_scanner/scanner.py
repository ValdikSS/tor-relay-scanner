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
    def grab(self):
        with requests.get(
            "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses",
            timeout=int(TIMEOUT),
        ) as r:
            return r.json()

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
    NUM_RELAYS = 15
    WORKING_RELAY_NUM_GOAL = 5
    MAX_NUM_TRIES = 3

    print("Downloading Tor Relay information from onionoo.torproject.org…", file=sys.stderr)
    relays = TorRelayGrabber().grab_parse()
    print("Done!", file=sys.stderr)

    working_relays = list()
    ntry = 0
    for ntry in range(MAX_NUM_TRIES):
        if len(working_relays) >= WORKING_RELAY_NUM_GOAL:
            break

        test_relays = [TorRelay(random.choice(relays))
                       for x in range(NUM_RELAYS)]
        print(
            f"\nTry {ntry}, We'll test the following {NUM_RELAYS} random relays:", file=sys.stderr)
        for relay in test_relays:
            print(relay, file=sys.stderr)
        print("", file=sys.stderr)

        print("Test started…", file=sys.stderr)
        tasks = list()
        for relay in test_relays:
            tasks.append(asyncio.create_task(relay.check()))
        fin = await asyncio.gather(*tasks)
        print("", file=sys.stderr)

        print("The following relays are reachable:", file=sys.stderr)
        for relay in test_relays:
            if relay:
                print(relay)
                working_relays.append(relay)
        if not test_relays:
            print("No relays are reachable.", file=sys.stderr)

    if ntry > 1:
        print("", file=sys.stderr)
        print("All reachable relays:", file=sys.stderr)
        for relay in working_relays:
            if relay:
                print(relay, file=sys.stderr)


def main():
    asyncio.run(main_async())
