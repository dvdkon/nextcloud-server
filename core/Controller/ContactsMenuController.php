<?php

declare(strict_types=1);
/**
 * @copyright 2017 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @author Christoph Wurst <christoph@winzerhof-wurst.at>
 * @author Georg Ehrke <oc.list@georgehrke.com>
 * @author Roeland Jago Douma <roeland@famdouma.nl>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */
namespace OC\Core\Controller;

use OC\Contacts\ContactsMenu\Manager;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\Contacts\ContactsMenu\IEntry;
use OCP\IRequest;
use OCP\IUserSession;

class ContactsMenuController extends \OCP\AppFramework\OCSController {

	/** @var Manager */
	private $manager;

	/** @var IUserSession */
	private $userSession;

	/**
	 * @param IRequest $request
	 * @param IUserSession $userSession
	 * @param Manager $manager
	 */
	public function __construct(IRequest $request, IUserSession $userSession, Manager $manager) {
		parent::__construct('core', $request);
		$this->userSession = $userSession;
		$this->manager = $manager;
	}

	/**
	 * @NoAdminRequired
	 *
	 * @param string|null filter
	 * @return DataResponse
	 */
	public function index(?string $filter = null): DataResponse {
		$data = $this->manager->getEntries($this->userSession->getUser(), $filter);

		$response = new DataResponse(array_map([$this, 'entryToArray'], $data['contacts']));
		$response->addHeader('X-Contacts-App-Enabled', $data['contactsAppEnabled'] ? 'yes' : 'no');
		return $response;
	}

	/**
	 * @NoAdminRequired
	 *
	 * @param integer $shareType
	 * @param string $shareWith
	 * @return DataResponse
	 */
	public function findOne(int $shareType, string $shareWith): DataResponse {
		$contact = $this->manager->findOne($this->userSession->getUser(), $shareType, $shareWith);

		if ($contact) {
			return new DataResponse($this->entryToArray($contact));
		}
		return new DataResponse([], Http::STATUS_NOT_FOUND);
	}

	protected function entryToArray(IEntry $entry): array {
		return json_decode(json_encode($entry), true);
	}
}
