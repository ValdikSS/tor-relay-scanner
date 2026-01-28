#!/usr/bin/env python3

import asyncio
import random
import sys
import ssl
import urllib.parse
import argparse
import subprocess
import os.path
import json
import requests

DESCRIPTION = "Downloads all Tor Relay IP addresses from onionoo.torproject.org and checks whether random Relays are available."


class TCPSocketConnectChecker:
    def __init__(self, host, port, timeout=10.0,
                 check_ssl=False, check_ssl_num_data=8):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.check_ssl = check_ssl
        self.check_ssl_num_data = check_ssl_num_data
        self.connection_status = None

    def __repr__(self):
        return "{}:{}".format(
            self.host if self.host.find(":") == -1 else "[" + self.host + "]",
            self.port)

    def random_tor_hostname(self):
        BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567"
        hostname = []

        for _ in range(random.randint(4, 25)):
            hostname.append(random.choice(BASE32_CHARS))

        return "www." + ''.join(hostname) + ".org"

    async def connect(self):
        TOR_HANDSHAKE_VERSIONS = b"\x00\x00\x07\x00\x06\x00\x03\x00\x04\x00\x05"
        TOR_NETINFO = b"\x00\x00\x00\x01\x08\x67\x9A\xBC\xDE\x04\x04\xC0\xA8\x01\x64\x01\x04\x04\xC0\xA8\x01\x64" + b"\x00" * 492
        TOR_BOGUS_CREATE = b"\x00\x00\x00\x05\x01" + b"\x00" * 509

        try:
            ssl_ctx = None
            server_hostname = None
            ssl_handshake_timeout = None
            if self.check_ssl:
                server_hostname = self.random_tor_hostname()
                ssl_handshake_timeout = self.timeout
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            # Open connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port,
                                        ssl=ssl_ctx,
                                        ssl_handshake_timeout=ssl_handshake_timeout,
                                        server_hostname=server_hostname),
                self.timeout)

            if self.check_ssl:
                writer.write(TOR_HANDSHAKE_VERSIONS)
                await writer.drain()
                readdata = await asyncio.wait_for(reader.read(64*1024), timeout=self.timeout)
                if len(readdata) and readdata[0:3] == TOR_HANDSHAKE_VERSIONS[0:3]:
                    if not self.check_ssl_num_data:
                        self.connection_status = True
                    else:
                        writer.write(TOR_NETINFO)
                        for _ in range(self.check_ssl_num_data):
                            writer.write(TOR_BOGUS_CREATE)
                            await writer.drain()
                            readdata = await asyncio.wait_for(reader.read(64*1024), timeout=self.timeout)
                        if len(readdata) and readdata[0:5] == TOR_BOGUS_CREATE[0:4] + b"\x04":
                            self.connection_status = True

            writer.close()
            await writer.wait_closed()

            if self.check_ssl:
                if self.connection_status:
                    return (True, None)
                return (False, None)

            return (True, None)
        except (OSError, asyncio.TimeoutError) as e:
            self.connection_status = False
            return (False, e)


class TorRelayGrabber:
    def __init__(self, timeout=10.0, proxy=None,
                 inputrelayfile=None, outputrelayfile=None,
                 relayfile_fallback=False):
        self.timeout = timeout
        self.proxy = {'https': proxy} if proxy else None
        self.inputrelayfile = inputrelayfile
        self.outputrelayfile = outputrelayfile
        self.relayfile_fallback = relayfile_fallback

    def _grab_file(self, inputfile):
        with open(inputfile, "r") as f:
            return json.loads(f.read())

    def _save_to_file(self, relaydata, outputfile):
        try:
            with open(outputfile, "w") as f:
                f.write(json.dumps(relaydata))
            return True
        except (ValueError, OSError) as e:
            print("Can't save Relay data to file: {}".format(repr(e)),
                    file=sys.stderr)
        return False

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

        if self.inputrelayfile and not self.relayfile_fallback:
            # Loading relay data from a file, no network involved
            return self._grab_file(self.inputrelayfile)

        for url in URLS:
            try:
                r = self._grab(url)
                if r:
                    if self.outputrelayfile:
                        self._save_to_file(r, self.outputrelayfile)
                    return r
            except Exception as e:
                print("Can't download Tor Relay data from/via {}: {}".format(
                    urllib.parse.urlparse(url).hostname, repr(e)
                ), file=sys.stderr)

        if self.inputrelayfile and self.relayfile_fallback:
            # Fallback to relay data from a file
            return self._grab_file(self.inputrelayfile)

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

    async def check(self, timeout=10.0,
                    check_ssl=False, check_ssl_num_data=0):
        for i in self.iptuples:
            s = TCPSocketConnectChecker(i[0], i[1], timeout=timeout,
                                        check_ssl=check_ssl,
                                        check_ssl_num_data=check_ssl_num_data)
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

    if args.prefsjs:
        if not os.path.isfile(args.prefsjs):
            print("Error: the --browser {} file does not exist!".format(args.prefsjs), file=sys.stderr)
            return 3

    print(f"Tor Relay Scanner. Will scan up to {WORKING_RELAY_NUM_GOAL}" +
          " working relays (or till the end)", file=sys.stderr)
    print("Downloading Tor Relay information from Tor Metrics…", file=sys.stderr)
    relays = TorRelayGrabber(timeout=TIMEOUT, proxy=args.proxy,
                             inputrelayfile=args.inputrelayfile,
                             outputrelayfile=args.outputrelayfile,
                             relayfile_fallback=args.relay_infile_fallback).grab_parse(args.url)
    if not relays:
        print("Tor Relay information can't be downloaded!", file=sys.stderr)
        return 1
    print("Done!", file=sys.stderr)

    random.shuffle(relays)

    if args.preferred_country:
        countries = {}
        exclude_countries = {}
        only_countries = {}
        for i, c in enumerate(args.preferred_country.split(",")):
            if c.startswith('!'):   # exclusive countries, include only it
                only_countries[c.lstrip('!')] = True

            if c.startswith('-'):   # excluded countries
                exclude_countries[c.lstrip('-')] = False
            else:
                # sorted countries,
                # only_countries also fall-thru here for sorting purposes
                countries[c.lstrip('!')] = i

        if only_countries:
            relays = filter(lambda x: only_countries.get(x.get("country"), False), relays)
            if exclude_countries or len(countries) != len(only_countries):
                print("Warning: you've set exclusive country(ies) with other sorted or excluded countries, using only exclusive list!", file=sys.stderr)
        if exclude_countries:
            relays = filter(lambda x: exclude_countries.get(x.get("country"), True), relays)
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
    ntry = -1
    for ntry, chunk in enumerate(chunked_list(relays, NUM_RELAYS)):
        if len(working_relays) >= WORKING_RELAY_NUM_GOAL:
            break

        relaynum = len(chunk)
        test_relays = [TorRelay(r) for r in chunk]

        print(
            f"\nAttempt {ntry+1}/{numtries}, We'll test the following {relaynum} random relays:", file=sys.stderr)
        for relay in test_relays:
            print(relay, file=sys.stderr)
        print(file=sys.stderr)

        if ntry:
            print(f"Found {len(working_relays)} good relays so far. Test {ntry+1}/{numtries} started…", file=sys.stderr)
        else:
            print(f"Test started…", file=sys.stderr)

        tasks = list()
        for relay in test_relays:
            tasks.append(asyncio.create_task(relay.check(TIMEOUT,
                                                         check_ssl=args.use_ssl,
                                                         check_ssl_num_data=args.ssl_num)))
        fin = await asyncio.gather(*tasks)
        print(file=sys.stderr)

        print("The following relays are reachable this test attempt:", file=sys.stderr)
        for relay in test_relays:
            if relay:
                print(str_list_with_prefix(BRIDGE_PREFIX, relay.reachables()), file=outstream)
                if sys.stdout != outstream:
                    print(str_list_with_prefix(BRIDGE_PREFIX, relay.reachables()), file=sys.stderr)
                working_relays.append(relay)
        if not any(test_relays):
            print("No relays are reachable this test attempt.", file=sys.stderr)

    if ntry > 1:
        print(file=sys.stderr)
        print("All reachable relays:", file=sys.stderr)
        for relay in working_relays:
            if relay:
                print(str_list_with_prefix(BRIDGE_PREFIX, relay.reachables()), file=sys.stderr)
        if not any(working_relays):
            print("No relays are reachable, at all.", file=sys.stderr)
    elif ntry == -1:
        print("No relays selected, nothing to test. Check your preferred-country filter and other settings.",
              file=sys.stderr)

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

    outstream.close()

    if args.start_browser:
        start_browser()


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-n', type=int, dest='num_relays', default=30, help='The number of concurrent relays tested (default: %(default)s)')
    parser.add_argument('-g', '--goal', type=int, dest='working_relay_num_goal', default=5, help='Test until at least this number of working relays are found (default: %(default)s)')
    parser.add_argument('-c', '--preferred-country', type=str, default="", help='Preferred/excluded/exclusive country list, comma-separated. Use "-" prefix to exclude the country, "!" to use only selected country. Example: se,gb,nl,-us,-de. Example for exclusive countries: !us,!tr')
    parser.add_argument('-s', '--ssl', action='store_true', dest='use_ssl', help='Simulate Tor SSL/TLS handshake and negotiate Tor protocol VERSIONS packet')
    parser.add_argument('--ssl-data-amount', type=int, dest='ssl_num', default=8, help='Try to create Tor Circuit n times (≈514 bytes exchange each)')
    parser.add_argument('--timeout', type=float, default=10.0, help='Socket connection timeout (default: %(default)s)')
    parser.add_argument('-o', '--outfile', type=argparse.FileType('w'), default=sys.stdout, help='Output reachable relays to file')
    parser.add_argument('--torrc', action='store_true', dest='torrc_fmt', help='Output reachable relays in torrc format (with "Bridge" prefix)')
    parser.add_argument('--proxy', type=str, help='Set proxy for onionoo information download (not for scan). Format: http://user:pass@host:port; socks5h://user:pass@host:port')
    parser.add_argument('--url', type=str, action='append', help='Preferred alternative URL for onionoo relay list. Could be used multiple times.')
    parser.add_argument('--relay-infile', dest='inputrelayfile', type=str, default="", help='Load relays from the file, do not download from the network')
    parser.add_argument('--relay-infile-fallback', action='store_true', help='Prefer relays from the network, fallback to --relay-infile when all network sources failed')
    parser.add_argument('--relay-outfile', dest='outputrelayfile', type=str, default="", help='Save relays downloaded from the network to the file')
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
