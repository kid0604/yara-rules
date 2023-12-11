rule Dos_NC
{
	meta:
		description = "Chinese Hacktool Set - file NC.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57f0839433234285cc9df96198a6ca58248a4707"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "invalid connection to [%s] from %s [%s] %d" fullword ascii
		$s3 = "post-rcv getsockname failed" fullword ascii
		$s4 = "Failed to execute shell, error = %s" fullword ascii
		$s5 = "UDP listen needs -p arg" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <290KB and all of them
}
