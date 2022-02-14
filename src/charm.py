#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import logging
import os

from charmhelpers.core import host
from charmhelpers.fetch.snap import snap_install
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus

logger = logging.getLogger(__name__)

SNAP_NAME = 'openidc-test-ipsilon'
SNAP_STORE = 'snap-store'
IPSILON_DAEMON = 'snap.%s.daemon' % SNAP_NAME


class OpenidcTestFixtureCharm(CharmBase):
    '''Charm the service.'''

    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.update_status, self._on_update_status)

        self._stored.set_default(snap_hash=None)
        self._stored.set_default(installation_source=None)

    def _on_install(self, _):
        '''Install the workload.'''

        self._install_snap_if_needed()
        self.unit.status = ActiveStatus('Installed.')

    def _on_config_changed(self, _):
        '''config-changed handler.'''
        self._install_snap_if_needed()
        self._on_update_status(_)

    def _install_snap_if_needed(self):
        '''Install or upgrade openidc-test-ipsilon if needed.'''
        ipsilon_fpath = self.model.resources.fetch('openidc-test-ipsilon')

        if ipsilon_fpath:
            snap_hash = self._hash_resource(ipsilon_fpath)
            if self._stored.snap_hash != snap_hash:
                logger.debug('Using resource attached to install %s', SNAP_NAME)
                snap_install(os.path.abspath(ipsilon_fpath),
                             '--dangerous', '--classic')
                self._stored.installation_method = 'resource'
                self._stored.snap_hash = snap_hash
            else:
                logger.debug('Snap resource has not changed.')
        elif self._stored.installation_method != SNAP_STORE:
            channel = self.config["snap-channel"]
            logger.debug('Installing %s from the snap store', SNAP_NAME)
            snap_install(SNAP_NAME, '--classic',
                         '--channel', channel)
            self._stored.installation_method = SNAP_STORE

    def _on_update_status(self, _):
        if host.service_running(IPSILON_DAEMON):
            status = ActiveStatus('%s running.' % IPSILON_DAEMON)
        else:
            status = BlockedStatus('%s not running' % IPSILON_DAEMON)

        self.unit.status = status

    def _hash_resource(self, fpath: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(fpath, 'rb') as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()


if __name__ == '__main__':
    main(OpenidcTestFixtureCharm)
