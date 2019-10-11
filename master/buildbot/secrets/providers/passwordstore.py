# This file is part of Buildbot.  Buildbot is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright Buildbot Team Members
"""
password store based provider
"""

import os
import subprocess
from glob import glob
from pathlib import Path

from buildbot import config
from buildbot.secrets.providers.base import SecretProviderBase


class SecretInPass(SecretProviderBase):
    """
    secret is stored in a password store
    """
    name = "SecretInPass"

    def checkPassDirectoryIsAvailableAndReadable(self, dirname):
        if not os.access(dirname, os.F_OK):
            config.error("directory %s does not exist" % dirname)

    def checkConfig(self, gpgPassphrase=None, dirname=None):
        if dirname:
            self.checkPassDirectoryIsAvailableAndReadable(dirname)

    def reconfigService(self, gpgPassphrase=None, dirname=None):
        self._env = {**os.environ}
        if gpgPassphrase:
            self.pw = gpgPassphrase
        else:
            self.pw = None

        if dirname is None:
            self.pw_dir = Path.home() / '.password-store'
        else:
            self.pw_dir = Path(dirname)

        self.secrets = set(s[:-4] for s in glob(f'{self.pw_dir}/**/*.gpg'))

    def get(self, entry):
        """
        get the value from pass identified by 'entry'
        """
        in_file = os.fspath(self.pw_dir / f'{entry}.gpg')
        if self.pw is None:
            gpg_args = tuple(['--batch', '-qd', in_file])
        else:
            gpg_args = tuple(['--batch', '--pinentry-mode', 'loopback', '--passphrase', self.pw, '-qd', in_file])
        try:
            stdout = subprocess.check_output(['gpg', *gpg_args], universal_newlines=True)

        except IOError:
            return None

        first_line = stdout.splitlines()[0]
        secret = first_line.strip()
        return secret
