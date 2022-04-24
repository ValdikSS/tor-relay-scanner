Tor Relay Availability Checker
==============================

This small script downloads all Tor Relay IP addresses from [onionoo.torproject.org](https://onionoo.torproject.org/) directly and via embedded proxies, and checks whether random Tor Relays are reachable from your Internet connection.

It could be used to find working Relay in a countries with Internet censorship and blocked Tor, and use it as Bridge to connect to Tor network, bypassing standard well-known nodes embedded into Tor code.

## How to use with Tor Browser

Works on Windows and Linux. Not tested on macOS.

1. Download latest version from [Releases](https://github.com/ValdikSS/tor-relay-scanner/releases) page.
2. Put the file into Tor Browser's directory.
3. **(Windows)**: Create a shortcut (link) to the file and append the following command line in shortcut settings: `-g 1 --timeout 3 --browser --start-browser`  
   **(Linux)** : Create a shortcut to the file, launching it using `python3`, and append the following arguments: `-g 1 --timeout 3 --browser --start-browser`.  
   The quick way to do this is to create a script with the following command:  
   `echo -e '#!/bin/sh\nexec python3' ./tor-relay-scanner-*.pyz '-g 1 --timeout 3 --browser --start-browser' > run.sh && chmod +x run.sh`
4. From now on, launch Tor Browser using the shortcut you've created in step 3. It will scan for reachable Relays, add it to Tor Browser configuration file (prefs.js), and launch the browser.


## How to use with Tor (daemon)

This utility is capable of generating `torrc` configuration file containing Bridge information. Launch it with the following arguments:

`--torrc --output /etc/tor/bridges.conf`

And append:

`%include /etc/tor/bridges.conf`

to the end of `/etc/tor/torrc` file to make Tor daemon load it.


## How to use as a standalone tool

**Windows**: download ***.exe** file from [Releases](https://github.com/ValdikSS/tor-relay-scanner/releases) and run it in console (`start → cmd`)

**Linux & macOS**: download ***.pyz** file from [Releases](https://github.com/ValdikSS/tor-relay-scanner/releases) and run it with Python 3.7+:  
`python3 tor-relay-scanner.pyz`
