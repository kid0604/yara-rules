rule Smartniff
{
	meta:
		description = "Chinese Hacktool Set - file Smartniff.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "67609f21d54a57955d8fe6d48bc471f328748d0a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "smsniff.exe" fullword wide
		$s2 = "support@nirsoft.net0" fullword ascii
		$s3 = "</requestedPrivileges></security></trustInfo></assembly>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
