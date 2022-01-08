<?php
/**
 * @copyright Copyright (c) 2021, David Koňařík (dvdkon@konarici.cz)
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
namespace OC\Files\Storage;

use Icewind\Streams\IteratorDirectory;
use OCP\Files\EmptyFileNameException;
use OCP\Files\FileNameTooLongException;
use OCP\Files\ForbiddenException;
use OCP\Files\StorageBadConfigException;
use OCP\Files\StorageConnectionException;
use OCP\Files\StorageAuthException;
use OCP\Files\StorageNotAvailableException;
use function array_key_exists;

class Deluacd extends Common {
	const MESSAGE_INIT = 1;
	const MESSAGE_STOP = 2;
	const MESSAGE_PING = 3;
	const MESSAGE_OPEN = 4;
	const MESSAGE_MKDIR = 5;
	const MESSAGE_UNLINK = 6;
	const MESSAGE_RMDIR = 7;
	const MESSAGE_RENAME = 8;
	const MESSAGE_ACCESS = 9;
	const MESSAGE_SCANDIR = 10;

	const RESPONSE_ERR = 0;
	const RESPONSE_OK = 1;
	const RESPONSE_FATAL_ERR = 2;

	const ACCESS_F_OK = 0;
	const ACCESS_X_OK = 1;
	const ACCESS_W_OK = 2;
	const ACCESS_R_OK = 4;

	const O_RDONLY = 0;
	const O_WRONLY = 1;
	const O_RDWR = 2;
	const O_APPEND = 1024;
	const O_EXCL = 128;
	const O_TRUNC = 512;
	const O_CLOEXEC = 524288;

	private $root;
	private $uid;
	private $socket;
	private $socketPath;
	private $key;
	private $creationMode;
	private $uidMapping; // UNIX numeric UID to NextCloud string username
	private $statCache; // Assoc. array path => stat result
	private $accessCache; // Assoc. array path => stat result

	//
	// Constructor/destructor
	//

	function __construct($params) {
		if(empty($params['root'])) {
			throw new StorageBadConfigException('Target root path required');
		}
		if(empty($params['socket'])) {
			throw new StorageBadConfigException('Path to socket required');
		}
		if(empty($params['key'])) {
			throw new StorageBadConfigException('Secret key required');
		}
		if(empty($params['uid'])) {
			throw new StorageBadConfigException('Target UID required');
		}
		if(!preg_match('/^[0-9]+$/', $params['uid'])) {
			throw new StorageBadConfigException('Target UID must be an integer');
		}

		$this->root = realpath($params['root']);
		if($this->root === false) {
			throw new StorageBadConfigException('Target root path does not exist: ' . $params['root']);
		}
		$this->socketPath = $params['socket'];
		$this->key = $params['key'];
		$this->uid = intval($params['uid']);
		$this->creationMode = octdec($params['creationMode'] ?? '755');
		$this->uidMapping = $params['uidMapping'] ?? [];
		$this->statCache = [];
	}

	function __destruct() {
		if($this->socket) {
			$this->send(pack('C', self::MESSAGE_STOP));
			$this->readCommonResp();
			socket_close($this->socket);
		}
	}

	//
	// Internal deluacd communication functions
	//

	private function delayedInit($reconnect = false) {
		if(!$this->socket || $reconnect) {
			$this->connect($this->socketPath, $this->key, $this->uid);
		}
	}

	private function connect(string $socketPath, string $secretKey, int $uid): void {
		$this->socket = socket_create(AF_UNIX, SOCK_STREAM, 0);
		if(!$this->socket)
			$this->throwIoError('Failure creating socket');

		if(!socket_connect($this->socket, $socketPath))
			$this->throwIoError('Failure connecting');

		// Send INIT message
		$this->send(
			pack('Cv', self::MESSAGE_INIT, strlen($secretKey)) .
			$secretKey .
			pack('V', $uid));
		$outCode = $this->readCommonResp();
		if($outCode !== self::RESPONSE_OK) {
			throw new StorageAuthException('Wrong secret key');
		}
	}

	private function send(string $msg): void {
		$this->delayedInit();
		if(socket_send($this->socket, $msg, strlen($msg), 0) !== strlen($msg))
			$this->throwIoError('Failure sending message');
	}

	private function read(int $length): string {
		$data = socket_read($this->socket, $length);
		if(!$data) {
			$this->throwIoError('Failure reading from socket');
		}
		return $data;
	}

	private function pingInternal(): void {
		$this->send(pack('C', self::MESSAGE_PING));
		$this->readCommonResp();
	}

	private function openInternal(string $path, int $flags, int $creationMode, bool $retrying = false) {
		$this->send(
			pack('Cv', self::MESSAGE_OPEN, strlen($path)) .
			$path .
			pack('VV', $flags, $creationMode));

		$recvData = [
			'name' => [],
			'buffer_size' => 2048,
			'controllen' => socket_cmsg_space(SOL_SOCKET, SCM_RIGHTS, 1)
		];
		if(!socket_recvmsg($this->socket, $recvData, 0))
			$this->throwIoError('Unable to receive open response');

		$msg = $recvData['iov'][0];
		if(strlen($msg) < 5) {
			$msg .= $this->read(4096); // Fetch the rest
		}
		$outCode = unpack('C', $msg)[1];
		$errno = unpack('V', $msg, 1)[1];

		if($outCode === self::RESPONSE_OK) {
			$fd = $recvData['control'][0]['data'][0];
			return $fd;
		} else if($outCode === self::RESPONSE_ERR) {
			if($errno == 24) { // EMFILE - too many open files
				// It seems files opened and then sent via UNIX sockets still
				// count towards a process' open file limit, and NextCloud can
				// try to open quite a few files in a single request.
				// As a workaround, we reconnect to the daemon, creating a new
				// request, and retry
				if(!$retrying) {
					$this->delayedInit(true);
					return $this->openInternal($path, $flags, $creationMode, true);
				} else {
					throw new StorageNotAvailableException('Too many files opened on deluacd daemon!');
				}
			}
			return -$errno;
		} else if($outCode == self::RESPONSE_FATAL_ERR) {
			$errlen = unpack('v', $msg, 1)[1];
			$errmsg = substr($msg, 3, $errlen);
			throw new StorageConnectionException('Fatal error: ' . $errmsg);
		}
	}

	private function mkdirInternal(string $path, int $mode): int|bool {
		$this->send(
			pack('Cv', self::MESSAGE_MKDIR, strlen($path)) .
			$path .
			pack('V', $mode));
		return $this->handleErrnoResp();
	}

	private function unlinkInternal(string $path): int|bool {
		$this->send(pack('Cv', self::MESSAGE_UNLINK, strlen($path)) . $path);
		return $this->handleErrnoResp();
	}

	private function rmdirInternal(string $path): int|bool {
		$this->send(pack('Cv', self::MESSAGE_RMDIR, strlen($path)) . $path);
		$outCode  = $this->readCommonResp();
		return $this->handleErrnoResp();
	}

	private function renameInternal(string $from, string $to): int|bool {
		$this->send(
			pack('Cv', self::MESSAGE_RMDIR, strlen($path)) . $path .
			pack('v', strlen($path)) . $path);
		return $this->handleErrnoResp();
	}

	private function accessInternal(string $path, int $mode): int|bool {
		$this->send(
			pack('Cv', self::MESSAGE_ACCESS, strlen($path)) . $path .
			pack('C', $mode));
		return $this->handleErrnoResp();
	}

	private function scandirInternal(string $path, bool $allFiles): array|bool {
		$this->send(
			pack('Cv', self::MESSAGE_SCANDIR, strlen($path)) . $path .
			pack('C', $allFiles ? 1 : 0));
		$ret = $this->handleErrnoResp();
		if($ret !== true) {
			return $ret;
		}
		$entries = [];
		while(true) {
			$len = unpack('v', $this->read(2))[1];
			if($len === 0) {
				break;
			}
			$entries[] = $this->read($len);
		}
		return $entries;
	}

	private function readCommonResp(): int {
		$code = unpack('C', $this->read(1))[1];
		if($code == self::RESPONSE_FATAL_ERR) {
			$errlen = unpack('v', $this->read(2))[1];
			throw new StorageConnectionException('Fatal eror: ' . $this->read($errlen));
		}
		return $code;
	}

	private function handleErrnoResp(): int|bool {
		$outCode  = $this->readCommonResp();
		$errno = unpack('V', $this->read(4))[1];
		if($outCode === self::RESPONSE_OK) {
			return true;
		} else {
			return false;
		}
	}

	private function throwIoError(string $msg): void {
		throw new StorageConnectionException($msg . ': ' . socket_strerror(socket_last_error()));
	}

	//
	// IStorage implementation
	//

	private function translatePath(string $path): string {
		$fullPath = $this->root . '/' . $path;
        $parts = explode('/', $fullPath);
        $resolvedParts = [];
        foreach ($parts as $part) {
            if ('.' === $part) continue;
            if ('..' === $part) {
                array_pop($resolvedParts);
            } else {
                $resolvedParts[] = $part;
            }
        }
        $resolvedPath = implode('/', $resolvedParts);

		if(!str_starts_with($resolvedPath, $this->root)) {
			throw new ForbiddenException('Path led out of storage root', false);
		}

		return $resolvedPath;
	}

	public function getId() {
		return 'deluacd::{$this->uid}::{$this->root}';
	}

	public function mkdir($path) {
		//trigger_error('Deluacd::mkdir() path=' . $path, E_USER_WARNING);
		return $this->mkdirInternal($this->translatePath($path), $this->creationMode) === true;
	}

	public function rmdir($path) {
		return $this->rmdirInternal($this->translatePath($path)) === true;
	}

	public function opendir($path) {
		$entries = $this->scandirInternal($this->translatePath($path), false);
		//trigger_error('Deluacd::opendir() path=' . $path, E_USER_WARNING);
		if($entries === false) {
			return false;
		}
		return IteratorDirectory::wrap($entries);
	}

	public function stat($path) {
		if(!array_key_exists($path, $this->statCache)) {
			// As a consequence of using fstat instead of stat, this will fail if
			// the file at $path isn't readable by the target user
			$fd = $this->fopen($path, 'r');
			if($fd === false) {
				return false;
			}
			$this->statCache[$path] = fstat($fd);
		}
		return $this->statCache[$path];
	}

	public function filetype($path) {
		$stat = $this->stat($path);
		if($stat === false) {
			return false;
		}
		if(($stat['mode'] >> 12) === 4) {
			return 'dir';
		}
		if(($stat['mode'] >> 12) === 8) {
			return 'file';
		}
		return 'unknown';
	}

	public function isCreatable($path) {
		if(!$this->file_exists($path)) {
			$path = dirname($path);
		}
		$res = $this->accessInternal(
			$this->translatePath($path), self::ACCESS_W_OK);
		//trigger_error('Deluacd::isCreatable() path=' . $path . ' -> ' . $res, E_USER_WARNING);
		return $res === true;
	}

	public function isReadable($path) {
		$res = $this->accessInternal(
			$this->translatePath($path), self::ACCESS_R_OK);
		//trigger_error('Deluacd::isReadable() path=' . $path . ' -> ' . $res, E_USER_WARNING);
		return $res === true;
	}

	public function isUpdatable($path) {
		$res = $this->accessInternal(
			$this->translatePath($path), self::ACCESS_W_OK);
		//trigger_error('Deluacd::isUpdatable() path=' . $path . ' -> ' . $res, E_USER_WARNING);
		return $res === true;
	}

	public function isDeletable($path) {
		if(!$this->file_exists($path)) {
			$path = dirname($path);
		}
		$res = $this->accessInternal(
			$this->translatePath($path), self::ACCESS_W_OK);
		//trigger_error('Deluacd::isDeletable() path=' . $path . ' -> ' . $res, E_USER_WARNING);
		return $res === true;
	}

	public function isSharable($path) {
		return true;
	}

	public function file_exists($path) {
		$res = $this->accessInternal(
			$this->translatePath($path), self::ACCESS_F_OK);
		//trigger_error('Deluacd::file_exists() path=' . $path . ' -> ' . $res, E_USER_WARNING);
		return $res === true;
	}

	public function unlink($path) {
		return $this->unlinkInternal($this->translatePath($path));
	}

	public function rename($path1, $path2) {
		return $this->renameInternal(
			$this->translatePath($path1),
			$this->translatePath($path2)) === true;
	}

	public function fopen($path, $mode) {
		//trigger_error('Deluacd::fopen() path=' . $path . ' mode=' . $mode, E_USER_WARNING);
		$mode = str_replace('t', '', str_replace('b', '', $mode));
		switch($mode) {
			case 'r': $flags = self::O_RDONLY; break;
			case 'r+': $flags = self::O_RDWR | self::O_TRUNC; break;
			case 'w': $flags = self::O_WRONLY | self::O_TRUNC | self::O_CREAT; break;
			case 'w+': $flags = self::O_RDWR | self::O_TRUNC | self::O_CREAT; break;
			case 'a': $flags = self::O_WRONLY | self::O_APPEND | self::O_CREAT; break;
			case 'a+': $flags = self::O_RDWR | self::O_APPEND | self::O_CREAT; break;
			case 'x': $flags = self::O_WRONLY | self::O_EXCL | self::O_CREAT; break;
			case 'x+': $flags = self::O_RDWR | self::O_EXCL | self::O_CREAT; break;
			case 'c': $flags = self::O_WRONLY | self::O_CREAT; break;
			case 'e': $flags = self::O_CLOEXEC; break;
			default: throw new \Exception('Invalid fopen mode: ' . $mode);
		}
		$fd = $this->openInternal(
			$this->translatePath($path), $flags, $this->creationMode);
		if($fd <= 0) {
			return false;
		} else {
			return $fd;
		}
	}

	public function free_space($path) {
		$fullPath = $this->translatePath($path);
		if (!is_dir($fullPath)) {
			$fullPath = dirname($fullPath);
		}
		$space = @disk_free_space($fullPath);
		if ($space === false || is_null($space)) {
			return \OCP\Files\FileInfo::SPACE_UNKNOWN;
		}
		return $space;
	}

	public function touch($path, $mtime = null) {
		if($mtime === null) {
			return $this->fopen($path, 'r') !== false;
		} else {
			return false;
		}
	}

	public function getETag($path) {
		// From Local::calculateEtag()
		$stat = $this->stat($path);
		if($stat === false) {
			return false;
		}
		if ($stat['mode'] & 0x4000 && !($stat['mode'] & 0x8000)) { // is_dir & not socket
			return parent::getETag($path);
		} else {
			if ($stat === false) {
				return md5('');
			}

			$toHash = '';
			if (isset($stat['mtime'])) {
				$toHash .= $stat['mtime'];
			}
			if (isset($stat['ino'])) {
				$toHash .= $stat['ino'];
			}
			if (isset($stat['dev'])) {
				$toHash .= $stat['dev'];
			}
			if (isset($stat['size'])) {
				$toHash .= $stat['size'];
			}

			return md5($toHash);
		}
	}

	public function test() {
		$this->pingInternal();
		return true;
	}

	public function getOwner($path) {
		//trigger_error('Deluacd::getOwner() path=' . $path, E_USER_WARNING);
		$stat = $this->stat($path);
		if($stat === false) {
			return false;
		}
		if(array_key_exists($stat['uid'], $this->uidMapping)) {
			return $this->uidMapping[$stat['uid']];
		} else {
			//return null;
			return \OC_User::getUser();
		}
	}
}

