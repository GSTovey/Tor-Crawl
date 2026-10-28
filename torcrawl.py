#!/usr/bin/python
"""
TorCrawl.py is a python script to crawl and extract (regular or onion)
webpages through TOR network.

usage: python torcrawl.py [options]
python torcrawl.py -u l0r3m1p5umD0lorS1t4m3t.onion
python torcrawl.py -v -w -u http://www.github.com -o github.htm
python torcrawl.py -v -u l0r3m1p5umD0lorS1t4m3t.onion -c -d 2 -p 5
python torcrawl.py -v -w -u http://www.github.com -c -d 2 -p 5 -e -f GitHub

General:
-h, --help         : Help
-v, --verbose      : Show more information about the progress
-u, --url *.onion  : URL of Webpage to crawl or extract
-w, --without      : Without the use of Relay TOR
-rua, --random-ua  : Enable random user-agent rotation for requests
-rpr, --random-proxy: Enable random proxy rotation from res/proxies.txt
-px, --proxy       : IP address for SOCKS5 proxy
-pr, --proxyport   : Port for SOCKS5 proxy
-V, --version      : Show version and exit

Extract:
-e, --extract           : Extract page's code to terminal or file.
                          (Default: terminal)
-i, --input filename    : Input file with URL(s) (separated by line)
-o, --output [filename] : Output page(s) to file(s) (for one page)
-y, --yara              : Yara keyword search page categorisation
                            read in from /res folder. 
                            'h' search whole html object.
                            't' search only the text.

Crawl:
-c, --crawl       : Crawl website (Default output on /links.txt)
-d, --depth       : Set depth of crawl's travel (Default: 1)
-p, --pause       : The length of time the crawler will pause (Default: 0)
-f, --folder      : The directory which will contain the generated files
-j, --json        : Export crawl findings to JSON in addition to txt outputs
-x, --xml         : Export crawl findings to XML in addition to txt outputs
-DB, --database   : Export crawl findings and link graph to SQLite database
-vis, --visualization: Generate HTML visualization (requires -DB)
-l, --log         : Log file with visited URLs and their response code.

GitHub: github.com/MikeMeliz/TorCrawl.py
License: GNU General Public License v3.0

"""

import argparse
import os
import socket
import sys
import datetime

import socks  # noqa - pysocks

from modules.checker import check_ip
from modules.checker import check_tor
from modules.checker import check_tor_port
from modules.checker import extract_domain
from modules.checker import folder
from modules.checker import url_canon
# TorCrawl Modules
from modules.crawler import Crawler
from modules.extractor import extractor
from modules.export import export_json, export_xml, export_database
from modules.visualization import export_visualization
# Proxy chain (Tor-over-Proxy)
from modules.proxychain import (
    FrontProxyConfig,
    TorrcManager,
    verify_proxy_chain,
    check_tcp_connection,
)

__version__ = "1.35"


# Set socket and connection with TOR network
def connect_tor(proxy_url, proxy_port):
    """ Connect to TOR via DNS resolution through a socket.
    :return: None or HTTPError.
    """
    try:
        # Set socks proxy and wrap the urllib module
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_url, proxy_port)
        socket.socket = socks.socksocket

        # Perform DNS resolution through the socket
        def getaddrinfo(*args):  # noqa
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '',
                     (args[0], args[1]))]

        socket.getaddrinfo = getaddrinfo  # noqa
    except socks.HTTPError as err:
        error = sys.exc_info()[0]
        print(f"Error: {error} \n## Cannot establish connection with TOR\n"
              f"HTTPError: {err}")


def main():
    """ Main method of TorCrawl application. Collects and parses arguments and
    instructs the rest of the application on how to run.

    :return: None
    """

    # Get arguments with argparse.
    parser = argparse.ArgumentParser(
        description="TorCrawl.py is a python script to crawl and extract "
                    "(regular or onion) webpages through TOR network.")

    # General
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Show more information about the progress'
    )
    parser.add_argument(
        '-u',
        '--url',
        help='URL of webpage to crawl or extract'
    )
    parser.add_argument(
        '-w',
        '--without',
        action='store_true',
        help='Without the use of Relay TOR'
    )
    parser.add_argument(
        '-V',
        '--version',
        action='version',
        version=f"%(prog)s {__version__}"
    )

    # Extract
    parser.add_argument(
        '-e',
        '--extract',
        action='store_true',
        help='Extract page\'s code to terminal or file.'
    )
    parser.add_argument(
        '-i',
        '--input',
        help='Input file with URL(s) (separated by line)'
    )
    parser.add_argument(
        '-o',
        '--output',
        help='Output page(s) to file(s) (for one page)'
    )

    # Crawl
    parser.add_argument(
        '-c',
        '--crawl',
        action='store_true',
        help='Crawl website (Default output on /links.txt)'
    )
    parser.add_argument(
        '-d',
        '--depth',
        help='Set depth of crawl\'s travel (Default: 1)'
    )
    parser.add_argument(
        '-p',
        '--pause',
        help='The length of time the crawler will pause'
    )
    parser.add_argument(
        '-l',
        '--log',
        action='store_true',
        help='A save log will let you see which URLs were visited and their '
             'response code'
    )
    parser.add_argument(
        '-f',
        '--folder',
        help='The root directory which will contain the generated files'
    )
    parser.add_argument(
        '-j',
        '--json',
        dest='json_export',
        action='store_true',
        help='Export crawl findings to JSON in addition to txt outputs'
    )
    parser.add_argument(
        '-x',
        '--xml',
        dest='xml_export',
        action='store_true',
        help='Export crawl findings to XML in addition to txt outputs'
    )
    parser.add_argument(
        '-DB',
        '--database',
        dest='database_export',
        action='store_true',
        help='Export crawl findings and link graph to SQLite database'
    )
    parser.add_argument(
        '-vis',
        '--visualization',
        dest='visualization',
        action='store_true',
        help='Generate HTML visualization from SQLite database (requires -DB)'
    )
    parser.add_argument(
        '-y',
        '--yara',
        help='Check for keywords and only scrape documents that contain a '
             'match. \'h\' search whole html object. \'t\' search only the text.'
    )
    parser.add_argument(
        '-rua',
        '--random-ua',
        action='store_true',
        help='Enable random user-agent rotation for requests'
    )
    parser.add_argument(
        '-rpr',
        '--random-proxy',
        action='store_true',
        help='Enable random proxy rotation from res/proxies.txt'
    )
    parser.add_argument(
        '-pr',
        '--proxyport',
        help='Port for SOCKS5 proxy',default=9050
    )
    parser.add_argument(
        '-px',
        '--proxy',
        help='IP address for SOCKS5 proxy',default='127.0.0.1'
    )

    # Tor-over-Proxy: upstream (front) proxy configuration
    parser.add_argument(
        '-up',
        '--upstream-proxy',
        help='Upstream (front) proxy address in host:port format '
             '(e.g. 127.0.0.1:7890 for Clash/V2Ray). '
             'When set, this proxy is configured as Tor\'s upstream '
             'via torrc so that Tor outbound connections go through it.'
    )
    parser.add_argument(
        '-upt',
        '--upstream-proxy-type',
        choices=['socks5', 'http'],
        default='socks5',
        help='Type of the local proxy interface exposed by the front proxy. '
             'socks5 (default) or http.'
    )
    parser.add_argument(
        '-upp',
        '--upstream-proxy-protocol',
        choices=['shadowsocks', 'trojan', 'vmess', 'vless'],
        default=None,
        help='Remote protocol used by the front proxy to reach its server. '
             'Informational only — the protocol itself is handled by '
             'Clash/V2Ray, not by this tool.'
    )
    parser.add_argument(
        '-tp',
        '--torrc-path',
        help='Path to the torrc configuration file. '
             'Auto-detected if not provided.'
    )
    parser.add_argument(
        '-ntc',
        '--no-torrc-config',
        action='store_true',
        help='Skip automatic torrc modification. '
             'Use this if you have already configured Tor\'s upstream proxy '
             'manually, or do not want this tool to modify torrc.'
    )
    parser.add_argument(
        '--verify-chain',
        action='store_true',
        help='Verify the full proxy chain (front proxy -> Tor -> target) '
             'before crawling.'
    )

    args = parser.parse_args()

    now = datetime.datetime.now().strftime("%y%m%d")
    results_prefix = f"{now}_results"

    # Canonicalization of web url and create path for output.
    website = ''
    output_folder = ''
    url_arg = args.url.strip() if args.url else ''

    if args.input:
        pass
    elif len(url_arg) > 0:
        website = url_canon(url_arg, args.verbose)
        if args.folder is not None:
            output_folder = folder(args.folder, args.verbose)
        else:
            output_folder = folder(extract_domain(website), args.verbose)
    else:
        print("## ERROR: URL is required unless --input is provided.")
        sys.exit(2)

    # Parse arguments to variables else initiate variables.
    input_file = args.input if args.input else ''
    output_file = args.output if args.output else ''
    depth = args.depth if args.depth else 0
    pause = args.pause if args.pause else 0
    selection_yara = args.yara if args.yara else None
    random_ua = args.random_ua
    random_proxy = args.random_proxy

    # Visualization requires database export.
    if args.visualization and not args.database_export:
        print("## Visualization requires --database (-DB) to generate the SQLite file.")
        sys.exit(2)

    # Random proxy rotation only works when TOR is disabled
    if random_proxy and args.without is False:
        print("## Warning: Random proxy rotation requires --without (-w) flag to disable TOR.")
        print("## Random proxy rotation disabled. Using TOR instead.")
        random_proxy = False

    # =====================================================================
    # Tor-over-Proxy: upstream (front) proxy via torrc management
    # =====================================================================
    upstream_config = None
    torrc_mgr = None

    if args.upstream_proxy and not args.no_torrc_config and not args.without:
        # Parse upstream proxy address
        try:
            if ':' in args.upstream_proxy:
                up_host, up_port = args.upstream_proxy.rsplit(':', 1)
                up_port = int(up_port)
            else:
                print("## ERROR: --upstream-proxy must be in host:port format "
                      "(e.g. 127.0.0.1:7890)")
                sys.exit(2)
        except (ValueError, TypeError):
            print("## ERROR: Invalid --upstream-proxy format. "
                  "Use host:port (e.g. 127.0.0.1:7890)")
            sys.exit(2)

        upstream_config = FrontProxyConfig(
            host=up_host,
            port=up_port,
            proxy_type=args.upstream_proxy_type,
            protocol=args.upstream_proxy_protocol,
        )

        if args.verbose:
            protocol_str = f" [{args.upstream_proxy_protocol}]" \
                if args.upstream_proxy_protocol else ""
            print(f"## Front proxy: {upstream_config.proxy_type}://"
                  f"{upstream_config.address}{protocol_str}")

        # Initialise TorrcManager and configure torrc
        torrc_mgr = TorrcManager(torrc_path=args.torrc_path)
        if torrc_mgr.torrc_path is None:
            print("## ERROR: Could not find torrc file.")
            print("## Specify path with --torrc-path or configure Tor "
                  "manually and use --no-torrc-config (-ntc).")
            sys.exit(2)

        if args.verbose:
            print(f"## Using torrc: {torrc_mgr.torrc_path}")

        torrc_mgr.set_upstream_proxy(
            proxy_type=upstream_config.proxy_type,
            host=upstream_config.host,
            port=upstream_config.port,
            verbose=args.verbose,
        )

        # Reload Tor to apply the new configuration
        if args.verbose:
            print("## Reloading Tor to apply upstream proxy config...")
        TorrcManager.reload_tor(verbose=args.verbose)
        print("## If Tor does not pick up the change, restart it manually.")

    elif args.upstream_proxy and args.no_torrc_config:
        # Manual mode: user has configured torrc themselves, just parse
        try:
            if ':' in args.upstream_proxy:
                up_host, up_port = args.upstream_proxy.rsplit(':', 1)
                up_port = int(up_port)
            else:
                print("## ERROR: --upstream-proxy must be in host:port format "
                      "(e.g. 127.0.0.1:7890)")
                sys.exit(2)
        except (ValueError, TypeError):
            print("## ERROR: Invalid --upstream-proxy format.")
            sys.exit(2)

        upstream_config = FrontProxyConfig(
            host=up_host,
            port=up_port,
            proxy_type=args.upstream_proxy_type,
            protocol=args.upstream_proxy_protocol,
        )
        if args.verbose:
            print(f"## Using existing front proxy config: "
                  f"{upstream_config.address} (manual torrc mode)")

    # =====================================================================
    # Chain verification (optional, before crawling)
    # =====================================================================
    if args.verify_chain and not args.without:
        upstream = upstream_config if upstream_config else None
        ok = verify_proxy_chain(
            tor_host=args.proxy,
            tor_port=args.proxyport,
            upstream=upstream,
            verbose=args.verbose,
        )
        if not ok:
            print("## Chain verification FAILED. "
                  "Use -w to skip Tor, or fix the configuration.")
            sys.exit(2)

    # Connect to TOR or random proxy
    if random_proxy:
        # Random proxy rotation enabled - will be handled per request
        if args.verbose:
            print("## Random proxy rotation enabled (TOR disabled)")
    elif args.without is False:
        check_tor(args.verbose, args.proxy, args.proxyport)
        connect_tor(args.proxy, args.proxyport)

    if args.verbose:
        check_ip()
        if args.url: print(('## URL: ' + args.url))

    if args.crawl:
        crawler = Crawler(website, depth, pause, output_folder, args.log,
                          args.verbose, random_ua, random_proxy)
        lst = crawler.crawl()

        if args.input is None:
            input_file = output_folder + '/' + now + '_links.txt'
      
        with open(input_file, 'w+', encoding='UTF-8') as file:
            for item in lst:
                file.write(f"{item}\n")
        print(f"## File created on {os.getcwd()}/{input_file}")

        if args.extract:
            extractor(website, args.crawl, output_file, input_file, output_folder,
                      selection_yara, random_ua, random_proxy)

        payload = crawler.export_payload()

        if args.json_export:
            export_json(output_folder, results_prefix, payload["data"], verbose=args.verbose)
        if args.xml_export:
            export_xml(output_folder, results_prefix, payload["data"], verbose=args.verbose)
        if args.database_export:
            export_database(output_folder, results_prefix, payload["data"], payload["edges"], payload["titles"], payload["resources"], verbose=args.verbose)
        if args.visualization:
            export_visualization(output_folder, results_prefix, payload["start_url"], verbose=args.verbose)
    else:
        extractor(website, args.crawl, output_file, input_file, output_folder,
                  selection_yara, random_ua, random_proxy)


# Stub to call main method.
if __name__ == "__main__":
    main()
