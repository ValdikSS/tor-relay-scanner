#!/usr/bin/env python3

import asyncio
import random
import sys
import urllib.parse
import argparse
import contextlib
import subprocess
import os.path
import requests

DESCRIPTION = "Downloads all Tor Relay IP addresses from onionoo.torproject.org and checks whether random Relays are available."


def format_host(host):
    """Format host string, adding brackets for IPv6 addresses."""
    return f'[{host}]' if ':' in host else host


class TCPSocketChecker:
    def __init__(self, host, port, timeout=10.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def __repr__(self):
        return f'{format_host(self.host)}:{self.port}'

    async def connect(self):
        try:
            # Open connection
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                self.timeout
            )
            # And close it
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            return False


class TorRelayGrabber:
    def __init__(self, timeout=10.0, proxy=None):
        self.timeout = timeout
        self.proxy = {'https': proxy} if proxy else None

    def _grab(self, url):
        response = requests.get(url, timeout=self.timeout, proxies=self.proxy)
        response.raise_for_status()
        return response.json()

    def grab(self, preferred_urls=None):
        base_url = "https://onionoo.torproject.org/details?type=relay&running=true&fields=fingerprint,or_addresses,country"
        urls = [
            base_url,
            f"https://icors.vercel.app/?{urllib.parse.quote(base_url)}",
            "https://github.com/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json",
            "https://bitbucket.org/ValdikSS/tor-onionoo-mirror/raw/master/details-running-relays-fingerprint-address-only.json",
        ]
        if preferred_urls:
            urls = preferred_urls + urls
        for url in urls:
            try:
                return self._grab(url)
            except Exception as e:
                print(f"Can't download Tor Relay data from/via {urllib.parse.urlparse(url).hostname}: {e}", file=sys.stderr)

    def grab_parse(self, preferred_urls=None):
        data = self.grab(preferred_urls)
        return data.get("relays", []) if data else []


class TorRelay:
    def __init__(self, relay_info):
        self.relay_info = relay_info
        self.fingerprint = relay_info["fingerprint"]
        self.ip_tuples = self._parse_or_addresses(relay_info["or_addresses"])
        self.reachable = []

    def reachables(self):
        return [f"{format_host(ip)}:{port} {self.fingerprint}" for ip, port in self.reachable]

    def __repr__(self):
        return "\n".join(self.reachables()) if self.reachable else str(self.relay_info)

    def __len__(self):
        return len(self.reachable)

    def _parse_or_addresses(self, or_addresses):
        result = []
        for address in or_addresses:
            parsed = urllib.parse.urlparse(f"//{address}")
            result.append((parsed.hostname, parsed.port))
        return result

    async def check(self, timeout=10.0):
        for ip, port in self.ip_tuples:
            checker = TCPSocketChecker(ip, port, timeout)
            if await checker.connect():
                self.reachable.append((ip, port))
        return bool(self.reachable)


def start_browser():
    browser_commands = ("Browser/start-tor-browser --detach", "Browser/firefox.exe")
    for cmd in browser_commands:
        if os.path.exists(cmd.split(" ")[0]):
            subprocess.Popen(cmd.split(" "))
            break


def join_with_prefix(prefix, items):
    return "\n".join(prefix + item for item in items)


def chunk_list(items, chunk_size):
    for i in range(0, len(items), chunk_size):
        yield items[i:i + chunk_size]


async def main_async(args):
    num_relays_to_test = args.num_relays
    timeout = args.timeout
    output_stream = args.outfile
    torrc_format = args.torrc_fmt
    bridge_prefix = "Bridge " if torrc_format else ""
    goal_reachable_relays = args.goal

    print(f"Tor Relay Scanner. Will scan up to {goal_reachable_relays} working relays (or until the end)", file=sys.stderr)
    print("Downloading Tor Relay information from Tor Metrics…", file=sys.stderr)
    relay_grabber = TorRelayGrabber(timeout=timeout, proxy=args.proxy)
    relays_info = relay_grabber.grab_parse(args.url)
    if not relays_info:
        print("Tor Relay information can't be downloaded!", file=sys.stderr)
        return 1
    print("Done!", file=sys.stderr)

    random.shuffle(relays_info)

    if args.preferred_country:
        preferred_countries = args.preferred_country.split(",")
        country_priority = {country: i for i, country in enumerate(preferred_countries)}
        relays_info.sort(key=lambda x: country_priority.get(x.get("country"), 1000))

    if args.port:
        filtered_relays_info = []
        for relay_info in relays_info:
            relay = TorRelay(relay_info)
            for ip, port in relay.ip_tuples:
                if port in args.port:
                    relay_copy = relay_info.copy()
                    relay_copy["or_addresses"] = [f"{format_host(ip)}:{port}"]
                    filtered_relays_info.append(relay_copy)
        relays_info = filtered_relays_info
        if not relays_info:
            print("There are no relays within specified port number constraints!", file=sys.stderr)
            print("Try changing port numbers.", file=sys.stderr)
            return 2

    working_relays = []
    num_attempts = (len(relays_info) + num_relays_to_test - 1) // num_relays_to_test
    for attempt_number, relay_chunk in enumerate(chunk_list(relays_info, num_relays_to_test)):
        if len(working_relays) >= goal_reachable_relays:
            break

        num_relays_in_chunk = len(relay_chunk)
        test_relays = [TorRelay(info) for info in relay_chunk]

        print(f"\nAttempt {attempt_number + 1}/{num_attempts}, testing {num_relays_in_chunk} random relays:", file=sys.stderr)
        for relay in test_relays:
            print(relay, file=sys.stderr)
        print(file=sys.stderr)

        if attempt_number:
            print(f"Found {len(working_relays)} good relays so far. Starting test {attempt_number + 1}/{num_attempts}…", file=sys.stderr)
        else:
            print("Test started…", file=sys.stderr)

        tasks = [asyncio.create_task(relay.check(timeout)) for relay in test_relays]
        await asyncio.gather(*tasks)
        print(file=sys.stderr)

        print("The following relays are reachable this attempt:", file=sys.stderr)
        for relay in test_relays:
            if relay.reachable:
                output = join_with_prefix(bridge_prefix, relay.reachables())
                print(output, file=output_stream)
                if output_stream != sys.stdout:
                    print(output, file=sys.stderr)
                working_relays.append(relay)
        if not any(relay.reachable for relay in test_relays):
            print("No relays are reachable this attempt.", file=sys.stderr)

    if attempt_number > 1:
        print(file=sys.stderr)
        print("All reachable relays:", file=sys.stderr)
        for relay in working_relays:
            if relay.reachable:
                print(join_with_prefix(bridge_prefix, relay.reachables()), file=sys.stderr)
        if not any(relay.reachable for relay in working_relays):
            print("No relays are reachable, at all.", file=sys.stderr)

    if working_relays:
        if torrc_format:
            print("UseBridges 1", file=output_stream)
        if args.prefsjs:
            try:
                with open(args.prefsjs, "r+") as f:
                    prefsjs_lines = [
                        line
                        for line in f
                        if "torbrowser.settings.bridges." not in line
                    ]
                    reachable_list = [relay_str for relay in working_relays for relay_str in relay.reachables()]
                    for num, relay_str in enumerate(reachable_list):
                        prefsjs_lines.append(f'user_pref("torbrowser.settings.bridges.bridge_strings.{num}", "{relay_str}");\n')
                    prefsjs_lines.extend([
                        'user_pref("torbrowser.settings.bridges.enabled", true);\n',
                        'user_pref("torbrowser.settings.bridges.source", 2);\n'
                    ])
                    f.seek(0)
                    f.truncate()
                    f.writelines(prefsjs_lines)
            except OSError as e:
                print("Can't open Tor Browser configuration:", e, file=sys.stderr)

    if args.start_browser:
        start_browser()


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-n', type=int, dest='num_relays', default=30, help='The number of concurrent relays tested.')
    parser.add_argument('-g', '--goal', type=int, dest='goal', default=5, help='Test until at least this number of working relays are found')
    parser.add_argument('-c', '--preferred-country', type=str, default="", help='Preferred country list, comma-separated. Example: se,gb,nl,de')
    parser.add_argument('--timeout', type=float, default=10.0, help='Socket connection timeout')
    parser.add_argument('-o', '--outfile', type=argparse.FileType('w'), default=sys.stdout, help='Output reachable relays to file')
    parser.add_argument('--torrc', action='store_true', dest='torrc_fmt', help='Output reachable relays in torrc format (with "Bridge" prefix)')
    parser.add_argument('--proxy', type=str, help='Set proxy for onionoo information download. Format: http://user:pass@host:port; socks5h://user:pass@host:port')
    parser.add_argument('--url', type=str, action='append', help='Preferred alternative URL for onionoo relay list. Can be used multiple times.')
    parser.add_argument('-p', type=int, dest='port', action='append', help='Scan for relays running on specified port number. Can be used multiple times.')
    parser.add_argument('--browser', type=str, nargs='?', metavar='/path/to/prefs.js', dest='prefsjs',
                        const='Browser/TorBrowser/Data/Browser/profile.default/prefs.js',
                        help='Install found relays into Tor Browser configuration file (prefs.js)')
    parser.add_argument('--start-browser', action='store_true', help='Launch browser after scanning')
    args = parser.parse_args()
    with contextlib.suppress(KeyboardInterrupt, SystemExit):
        asyncio.run(main_async(args))


if __name__ == '__main__':
    main()