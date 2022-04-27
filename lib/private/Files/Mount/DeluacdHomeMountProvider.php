<?php
/**
 * @copyright Copyright (c) 2022, David Koňařík (dvdkon@konarici.cz)
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
namespace OC\Files\Mount;

use OCP\Files\Config\IHomeMountProvider;
use OCP\Files\Storage\IStorageFactory;
use OCP\IConfig;
use OCP\IUser;

class DeluacdHomeMountProvider implements IHomeMountProvider {
	private IConfig $config;
	public function __construct(IConfig $config) {
		$this->config = $config;
	}

	/**
	 * Get all mountpoints applicable for the user
	 * @return \OCP\Files\Mount\IMountPoint|null
	 */
	public function getHomeMountForUser(IUser $user, IStorageFactory $loader) {
		$config = $this->config->getSystemValue('deluacd');
		if($config === null) {
			return null;
		}

		if($this->config->getUserValue($user->getUID(), 'user_ldap', 'unixUid') === '') {
			\OC::$server->getLogger()->debug('Not using Deluacd for home mount of '. $user->getUID() . ', user doesn\'t have UNIX UID');
			return null;
		}

		return new MountPoint(
			'\OC\Files\Storage\Deluacd',
			'/' . $user->getUID() . '/files',
			[
				'root' => str_replace('%u', $user->getUID(), $config['userRoot']),
				'socket' => $config['socket'],
				'key' => $config['key'],
				'creationMode' => $config['creationMode'],
				'username' => $user->getUID(),
			],
			$loader);
	}
}
