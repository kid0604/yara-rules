rule APT_RU_Sandworm_PY_May20_2
{
	meta:
		description = "Detects Sandworm Python loader"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/billyleonard/status/1266054881225236482"
		date = "2020-05-28"
		hash1 = "abfa83cf54db8fa548942acd845b4f34acc94c46d4e1fb5ce7e97cc0c6596676"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "import sys;import re, subprocess;cmd" ascii fullword
		$x2 = "UA='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';server='http"
		$x3 = "';t='/admin/get.php';req" ascii
		$x4 = "ps -ef | grep Little\\ Snitch | grep " ascii fullword

	condition:
		uint16(0)==0x6d69 and filesize <2KB and 1 of them
}
