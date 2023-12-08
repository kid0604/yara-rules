rule Dos_iis7
{
	meta:
		description = "Chinese Hacktool Set - file iis7.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\\\localhost" fullword ascii
		$s1 = "iis.run" fullword ascii
		$s3 = ">Could not connecto %s" fullword ascii
		$s5 = "WHOAMI" ascii
		$s13 = "WinSta0\\Default" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <140KB and all of them
}
