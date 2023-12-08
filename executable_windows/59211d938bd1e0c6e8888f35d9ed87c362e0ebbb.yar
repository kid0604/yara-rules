rule SwitchSniffer
{
	meta:
		description = "Chinese Hacktool Set - file SwitchSniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "NextSecurity.NET" fullword wide
		$s2 = "SwitchSniffer Setup" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them
}
