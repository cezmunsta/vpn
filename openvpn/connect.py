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
import shlex
import subprocess
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
MAX_ATTEMPTS = 3
#LASTPASS_CMD = 'lpass'
OPENVPN_CMD = 'sudo openvpn --config'
# TODO: the kill command currently expects just one OpenVPN connection, or will kill all ;)  # pylint: disable=fixme
OPENVPN_KILL_CMD = 'sudo pkill -QUIT -x openvpn'
CREDENTIALS_SOURCE = './credentials.yaml.asc'

__all__ = []
__version__ = 0.1



class OpenVPN:
    """
    OpenVPN controller
    """
    EXCLUDES = ['credentials']

    def __init__(self):
        self._storage = {}

        options = self.parse_args()

        self._storage['credentials_source'] = options['gpg_source']
        self._storage['config'] = options['config']
        self._storage['dry_run'] = options['dry_run']
        self._storage['use_duo'] = options['duo']
        self._storage['verbose_mode'] = options['verbose']
        self._storage['debug_mode'] = options['debug']
        self._storage['timeout'] =  options['timeout']

        self._storage['gpg'] = GPG_BINARY
        self._storage['gpg_use_agent'] = GPG_AGENT_ENABLED

        self._storage['credentials'] = {
            'marker': options['CREDENTIALS'],
            'use_lastpass': (options.get('lastpass'), options.get('username'))
        }
        self.log.info('Initialising VPN connection')

    def __getattr__(self, attr):
        if attr in self._storage and attr not in self.EXCLUDES:
            return self._storage[attr]
        return None

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
        extras_group.add_argument('--timeout', default=60, type=int, help='Configure the timeout threshold')
        extras_group.add_argument('--dry-run', '--simulate', action='store_true',
                                  help='Run through the motions, but take no action')
        extras_group.add_argument('--verbose', action='store_true',
                                  help='Increase verbosity of output')
        extras_group.add_argument('--debug', action='store_true',
                                  help='Debug output')
        return vars(parser.parse_args())


    def connect(self, attempts:int=0):
        """
        Connect to the VPN
        """
        cmd = f'{OPENVPN_CMD} {self.config}'
        credentials = self.lookup_credentials(**self._storage['credentials'])
        if self.dry_run:
            self.log.debug('Dry-run requested')
            print(cmd)
            return True

        try:
            self.log.debug('Executing cmd: %s', cmd)
            child = pexpect.spawn(cmd)
            self.log.debug('Waiting for username request')
            child.expect('Enter Auth Username:')
            self.log.debug('Responding to username request')
            child.sendline(credentials[0])
            self.log.debug('Waiting for password request')
            child.expect('Enter Auth Password:')
            self.log.debug('Responding to password request')
            child.sendline(credentials[1])
        finally:
            del credentials

        if self.use_duo:
            self.log.debug('Waiting for Duo request')
            child.expect('CHALLENGE: Duo passcode or second factor.*')
            self.log.debug('Responding to Duo request')
            child.sendline('push')

        while child.isalive():
            self.log.debug('Starting loop with child.isalive')
            try:
                credentials = self.lookup_credentials(**self._storage['credentials'])
                self.log.debug('Waiting for re-auth request')
                index = child.expect(['Enter Auth Password:', pexpect.TIMEOUT, pexpect.EOF],
                                     timeout=self.timeout)
                if index == 0:
                    self.log.debug('Responding to re-auth request')
                    child.sendline(credentials[1])
                    if self.use_duo:
                        child.expect('CHALLENGE: Duo passcode or second factor.*')
                        child.sendline('push')
                elif index == 1:
                    self.log.debug('Skipping to wait for re-auth request')
                    continue
                else:
                    self.log.debug('Bailing out of loop')
                    break
            finally:
                del credentials
        self.log.debug('Waiting for child process')
        child.wait()
        self.log.debug('Closing child process')
        child.close()
        self.log.info('Child process exited: %s, %s', child.exitstatus, child.signalstatus)

        if attempts < MAX_ATTEMPTS:
            self.connect(attempts + 1)
        return child.exitstatus, child.signalstatus


    def lookup_credentials(self, marker:str, use_lastpass:tuple=()):
        """
        Lookup encrypted credentials
        """
        data = {}
        self.log.debug('Looking up credentials')

        if len(use_lastpass) == 2 and bool(use_lastpass[0]):  # pylint: disable=no-else-raise
            self.log.debug('Attempting LastPass lookup')
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
            self.log.debug('Attempting GPG lookup')
            gpg = gnupg.GPG(gpgbinary=self.gpg, use_agent=self.gpg_use_agent,
                            verbose=self.debug_mode)

            with open(self.credentials_source, 'rb') as ct:  # pylint: disable=invalid-name
                self.log.debug('Decrypting file %s', self.credentials_source)
                pt = gpg.decrypt_file(ct)  # pylint: disable=invalid-name
                data = yaml.safe_load(pt.data.decode('utf8')).get(marker)
        try:
            credentials = (data['user'].rstrip(), data['pass'].rstrip(),)
            self.log.debug('Credentials loaded')
        except KeyError:
            self.log.error('Credentials failed to load')
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
            logging.basicConfig(level=logging.INFO if self.verbose_mode
                                else logging.DEBUG if self.debug_mode else logging.WARNING,
                                format=BASE_LOG_FORMAT)
            #console = logging.StreamHandler()
            #console.setLevel(logging.WARNING)
            #console.setFormatter(logging.Formatter(fmt=BASE_LOG_FORMAT))
            self._storage['logger'] = logging.getLogger('')
            #self._storage['logger'].addHandler(console)
        return self._storage['logger']

    def terminate(self):
        """
        Terminate the OpenVPN connection
        """
        try:
            cmd = subprocess.run(shlex.split(OPENVPN_KILL_CMD), capture_output=True, check=True)
            self.log.debug('Terminated connection: %r', cmd)
        except subprocess.CalledProcessError:
            self.log.exception('Failed to terminate connections')


def main():
    """
    Main method
    """
    vpn = OpenVPN()
    exitstatus = 0
    try:
        vpn.log.info('Starting VPN')
        exitstatus = vpn.connect()
    except IndexError:
        vpn.log.error('Failed to connect to VPN')
    except pexpect.exceptions.EOF:
        vpn.log.exception('A connection problem occurred')
    finally:
        vpn.terminate()
        sys.exit(exitstatus)


if __name__ == '__main__':
    main()
