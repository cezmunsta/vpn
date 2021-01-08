#!/usr/bin/env python3
"""
Connect to OpenVPN

Encrypted credentials should be stored in the following format:

---
<marker>:
  user: <username>
  pass: <password>
...

Multiple marker entries can be used in the same file as the code will
lookup the one that was requested for use.
"""

import argparse
import logging
import os
import sys

import gnupg
import pexpect
import yaml


ARGS = None
BASE_LOG_FORMAT = ' '.join([
    '%(asctime)s',
    '%(levelname)s:%(name)s:',
    'PID<%(process)d>',
    '%(module)s.%(funcName)s',
    '- %(message)s'
])
GPG_AGENT_ENABLED = True
GPG_BINARY = '/usr/bin/gpg'
#LASTPASS_CMD = 'lpass'
OPENVPN_CMD = 'sudo openvpn --config'
CREDENTIALS_SOURCE = './credentials.yaml.asc'

__all__ = []
__version__ = 0.1



class OpenVPN:
    """
    OpenVPN controller
    """
    def __init__(self):
        self._storage = {}

        options = self.parse_args()

        self.credentials_source = options['gpg_source']
        self.config = options['config']
        self.dry_run = options['dry_run']
        self.use_duo = options['duo']

        self.gpg = GPG_BINARY
        self.gpg_use_agent = GPG_AGENT_ENABLED

        self._storage['credentials'] = {
            'marker': options['CREDENTIALS'],
            'use_lastpass': (options.get('lastpass'), options.get('username'))
        }

    @staticmethod
    def parse_args():
        """
        Parse runtime arguments
        """
        parser = argparse.ArgumentParser(prog=os.path.basename(__file__),
                                         description='Connect to OpenVPN')
        main_group = parser.add_argument_group('main options')
        main_group.add_argument('CREDENTIALS', metavar='CREDENTIALS', nargs='?',
                                help='Specify the user for the connection [%(default)s]')
        main_group.add_argument('--config', default=None, required=True,
                                help='Specify the config to use')
        main_group.add_argument('--duo', action='store_true', default=True,
                                help='Require DUO authentication [%(default)s]')
        main_group.add_argument('--gpg', action='store_true', default=True,
                                help='Use GPG for credentials [%(default)s]')
        #main_group.add_argument('--lastpass', action='store_true',
        #                        help='Use LastPass for credentials [%(default)s]')
        ### TODO: use argparser.UsageGroup/Action to control this - for now testing args # pylint: disable=fixme
        #main_group.add_argument('--username', default=None, required='--lastpass' in sys.argv,
        #                        help='LastPass username [%(default)s]')
        main_group.add_argument('--gpg-source', default=CREDENTIALS_SOURCE,
                                required='--gpg' in sys.argv,
                                help='GPG-encrypted source [%(default)s]')

        extras_group = parser.add_argument_group('extra options')
        extras_group.add_argument('--dry-run', '--simulate', action='store_true',
                                  help='Run through the motions, but take no action')
        return vars(parser.parse_args())


    def connect(self):
        """
        Connect to the VPN
        """
        cmd = f'{OPENVPN_CMD} {self.config}'
        credentials = self.lookup_credentials(**self._storage['credentials'])
        if self.dry_run:
            print(cmd)
            return True

        try:
            child = pexpect.spawn(cmd)
            child.expect('Enter Auth Username:')
            child.sendline(credentials[0])
            child.expect('Enter Auth Password:')
            child.sendline(credentials[1])
        finally:
            del credentials

        if self.use_duo:
            child.expect('CHALLENGE: Duo passcode or second factor.*')
            child.sendline('push')
        child.wait()
        return True


    def lookup_credentials(self, marker:str, use_lastpass:tuple=()):
        """
        Lookup encrypted credentials
        """
        data = {}

        if len(use_lastpass) == 2 and bool(use_lastpass[0]):  # pylint: disable=no-else-raise
            raise NotImplementedError('LastPass support coming soon!')
            #_, initial_status = pexpect.run(f'{LASTPASS_CMD} status', withexitstatus=1)

            #if initial_status > 0:
            #    auth = 'login {0}'.format(use_lastpass[1])
            #    _, exit_status = pexpect.run(f'{LASTPASS_CMD} {auth}', withexitstatus=1)
            #    if exit_status > 0:
            #        raise RuntimeError('Unable to login to LastPass')
            #data['user'] = pexpect.run(f'{LASTPASS_CMD} show --username {marker}')
            #data['pass'] = pexpect.run(f'{LASTPASS_CMD} show --password {marker}')

            #if initial_status > 0:
            #    pexpect.run(f'{LASTPASS_CMD} logout --force')
        else:
            gpg = gnupg.GPG(gpgbinary=self.gpg, use_agent=self.gpg_use_agent, verbose=True)

            with open(self.credentials_source, 'rb') as ct:  # pylint: disable=invalid-name
                pt = gpg.decrypt_file(ct)  # pylint: disable=invalid-name
                data = yaml.safe_load(pt.data.decode('utf8')).get(marker)
        try:
            credentials = (data['user'].rstrip(), data['pass'].rstrip(),)
        except KeyError:
            return ()
        finally:
            del pt
            del data
        return credentials

    @property
    def log(self):
        """
        Access the logger
        """
        if 'logger' not in self._storage:
            logging.basicConfig(level=logging.INFO, format=BASE_LOG_FORMAT)
            console = logging.StreamHandler()
            console.setLevel(logging.WARNING)
            console.setFormatter(logging.Formatter(fmt=BASE_LOG_FORMAT))
            self._storage['logger'] = logging.getLogger('').addHandler(console)
        return self._storage['logger']


def main():
    """
    Main method
    """
    vpn = OpenVPN()
    try:
        vpn.connect()
    except IndexError:
        vpn.log.error('Failed to connect to VPN')


if __name__ == '__main__':
    main()
