#!/usr/bin/env python3

import asyncio
import random
import sys
import urllib.parse
import argparse
import subprocess
import os.path
import requests

DESCRIPTION = "Downloads all Tor Relay IP addresses from onionoo.torproject.org and checks whether random Relays are available."

class TCPSocketConnectChecker:
    def __init__(self, host, port, timeout=10.0):
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
                asyncio.open_connection(self.host, self.port), self.timeout)
            # And close it
            writer.close()
            await writer.wait_closed()
            self.connection_status = True
            return (True, None)
        except (OSError, asyncio.TimeoutError) as e:
            self.connection_status = False
            return (False, e)

class TorRelayGrabber:
    def __init__(self, timeout=10.0, proxy=None):
        self.timeout = timeout
        self.proxy = {'https': proxy} if proxy else None

    def _grab(self, url):
        with requests.get(url, timeout=int(self.timeout), proxies=self.proxy) as r:
            return r.json()

    def grab(self, preferred_urls_list=None):
        BASEURL = "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses,country"
        # Use public CORS proxy as a regular proxy in case if onionoo.torproject.org is unreachable
        URLS = [BASEURL,
                "https://icors.vercel.app/?" + urllib.parse.quote(BASEURL),
                "https://github.com/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json",
                "https://bitbucket.org/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json"]
        if preferred_urls_list:
            for pref_url in preferred_urls_list:
                URLS.insert(0, pref_url)

        for url in URLS:
            try:
                return self._grab(url)
            except Exception as e:
                print("Can't download Tor Relay data from/via {}: {}".format(
                    urllib.parse.urlparse(url).hostname, e
                ), file=sys.stderr)

    def grab_parse(self, preferred_urls_list=None):
        grabbed = self.grab(preferred_urls_list)
        if grabbed:
            grabbed = grabbed["relays"]
        return grabbed


class TorRelay:
    def __init__(self, relayinfo):
        self.relayinfo = relayinfo
        self.fingerprint = relayinfo["fingerprint"]
        self.iptuples = self._parse_or_addresses(relayinfo["or_addresses"])
        self.reachable = list()

    def reachables(self):
        r = list()
        for i in self.reachable:
            r.append("{}:{} {}".format(i[0] if i[0].find(":") == -1 else "[" + i[0] + "]",
                                i[1],
                                self.fingerprint,))
        return r

    def _reachable_str(self):
        return "\n".join(self.reachables())

    def __repr__(self):
        if not self.reachable:
            return str(self.relayinfo)
        return self._reachable_str()

    def __len__(self):
        return len(self.reachable)

    def _parse_or_addresses(self, or_addresses):
        ret = list()
        for address in or_addresses:
            parsed = urllib.parse.urlparse("//" + address)
            ret.append((parsed.hostname, parsed.port))
        return ret

    async def check(self, timeout=10.0):
        for i in self.iptuples:
            s = TCPSocketConnectChecker(i[0], i[1], timeout=timeout)
            sc = await s.connect()
            if sc[0]:
                self.reachable.append(i)

        return bool(self.reachable)


def start_browser():
    browser_cmds=("Browser/start-tor-browser --detach", "Browser/firefox.exe")
    for cmd in browser_cmds:
        if os.path.exists(cmd.split(" ")[0]):
            subprocess.Popen(cmd.split(" "))
            break


def str_list_with_prefix(prefix, list_):
    return "\n".join(prefix + r for r in list_)


def chunked_list(l, size):
    for i in range(0, len(l), size):
        yield l[i:i+size]


async def main_async(args):
    NUM_RELAYS = args.num_relays
    WORKING_RELAY_NUM_GOAL = args.working_relay_num_goal
    TIMEOUT = args.timeout
    outstream = args.outfile
    torrc_fmt = args.torrc_fmt
    BRIDGE_PREFIX = "Bridge " if torrc_fmt else ""

    print(f"Tor Relay Scanner. Will scan up to {WORKING_RELAY_NUM_GOAL}" +
          " working relays (or till the end)", file=sys.stderr)
    print("Downloading Tor Relay information from Tor Metrics…", file=sys.stderr)
    relays = TorRelayGrabber(timeout=TIMEOUT, proxy=args.proxy).grab_parse(args.url)
    if not relays:
        print("Tor Relay information can't be downloaded!", file=sys.stderr)
        return 1
    print("Done!", file=sys.stderr)

    random.shuffle(relays)

    if args.preferred_country:
        countries = {}
        for i, c in enumerate(args.preferred_country.split(",")):
            countries[c] = i
        # 1000 is just a sufficiently large number for default sorting
        relays = sorted(relays, key=lambda x: countries.get(x.get("country"), 1000))

    if args.port:
        relays_new = list()
        for relay in relays:
            for ipport in TorRelay(relay).iptuples:
                if ipport[1] in args.port:
                    # deep copy needed here, otherwise subsequent loop
                    # modifies "previous" value
                    relay_copy = relay.copy()
                    relay_copy["or_addresses"] = ["{}:{}".format(
                        ipport[0] if ipport[0].find(":") == -1 else "[" + ipport[0] + "]",
                        ipport[1])
                    ]
                    relays_new.append(relay_copy)
        relays = relays_new
        if not relays:
            print("There are no relays within specified port number constraints!", file=sys.stderr)
            print("Try changing port numbers.", file=sys.stderr)
            return 2

    working_relays = list()
    numtries = (len(relays) + NUM_RELAYS - 1) // NUM_RELAYS
    for ntry, chunk in enumerate(chunked_list(relays, NUM_RELAYS)):
        if len(working_relays) >= WORKING_RELAY_NUM_GOAL:
            break

        relaynum = len(chunk)
        test_relays = [TorRelay(r) for r in chunk]

        print(
            f"\nTry {ntry+1}/{numtries}, We'll test the following {relaynum} random relays:", file=sys.stderr)
        for relay in test_relays:
            print(relay, file=sys.stderr)
        print(file=sys.stderr)

        if ntry:
            print(f"Found {len(working_relays)} good relays so far. Test {ntry+1}/{numtries} started…", file=sys.stderr)
        else:
            print(f"Test started…", file=sys.stderr)

        tasks = list()
        for relay in test_relays:
            tasks.append(asyncio.create_task(relay.check(TIMEOUT)))
        fin = await asyncio.gather(*tasks)
        print(file=sys.stderr)

        print("The following relays are reachable this try:", file=sys.stderr)
        for relay in test_relays:
            if relay:
                print(str_list_with_prefix(BRIDGE_PREFIX, relay.reachables()), file=outstream)
                if sys.stdout != outstream:
                    print(str_list_with_prefix(BRIDGE_PREFIX, relay.reachables()), file=sys.stderr)
                working_relays.append(relay)
        if not any(test_relays):
            print("No relays are reachable this try.", file=sys.stderr)

    if ntry > 1:
        print(file=sys.stderr)
        print("All reachable relays:", file=sys.stderr)
        for relay in working_relays:
            if relay:
                print(str_list_with_prefix(BRIDGE_PREFIX, relay.reachables()), file=sys.stderr)
        if not any(working_relays):
            print("No relays are reachable, at all.", file=sys.stderr)

    if any(working_relays):
        if torrc_fmt:
            print("UseBridges 1", file=outstream)
        if args.prefsjs:
            try:
                with open(args.prefsjs, "r+") as f:
                    prefsjs = str()
                    for line in f:
                        if "torbrowser.settings.bridges." not in line:
                            prefsjs += line
                    # Ugly r.reachables() array flattening, as it may have more than one reachable record.
                    for num, relay in enumerate(sum([r.reachables() for r in working_relays], [])):
                        prefsjs += f'user_pref("torbrowser.settings.bridges.bridge_strings.{num}", "{relay}");\n'
                    prefsjs += 'user_pref("torbrowser.settings.bridges.enabled", true);\n'
                    prefsjs += 'user_pref("torbrowser.settings.bridges.source", 2);\n'
                    f.seek(0)
                    f.truncate()
                    f.write(prefsjs)
            except OSError as e:
                print("Can't open Tor Browser configuration:", e, file=sys.stderr)

    if args.start_browser:
        start_browser()


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-n', type=int, dest='num_relays', default=30, help='The number of concurrent relays tested (default: %(default)s)')
    parser.add_argument('-g', '--goal', type=int, dest='working_relay_num_goal', default=5, help='Test until at least this number of working relays are found (default: %(default)s)')
    parser.add_argument('-c', '--preferred-country', type=str, default="", help='Preferred country list, comma-separated. Example: se,gb,nl,de')
    parser.add_argument('--timeout', type=float, default=10.0, help='Socket connection timeout (default: %(default)s)')
    parser.add_argument('-o', '--outfile', type=argparse.FileType('w'), default=sys.stdout, help='Output reachable relays to file')
    parser.add_argument('--torrc', action='store_true', dest='torrc_fmt', help='Output reachable relays in torrc format (with "Bridge" prefix)')
    parser.add_argument('--proxy', type=str, help='Set proxy for onionoo information download (not for scan). Format: http://user:pass@host:port; socks5h://user:pass@host:port')
    parser.add_argument('--url', type=str, action='append', help='Preferred alternative URL for onionoo relay list. Could be used multiple times.')
    parser.add_argument('-p', type=int, dest='port', action='append', help='Scan for relays running on specified port number. Could be used multiple times.')
    parser.add_argument('--browser', type=str, nargs='?', metavar='/path/to/prefs.js', dest='prefsjs',
                        const='Browser/TorBrowser/Data/Browser/profile.default/prefs.js',
                        help='Install found relays into Tor Browser configuration file (prefs.js)')
    parser.add_argument('--start-browser', action='store_true', help='Launch browser after scanning')
    args = parser.parse_args()
    try:
        return asyncio.run(main_async(args))
    except (KeyboardInterrupt, SystemExit):
        pass
