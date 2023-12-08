rule sql1433_SQL
{
	meta:
		description = "Chinese Hacktool Set - file SQL.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "025e87deadd1c50b1021c26cb67b76b476fafd64"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 31 00 34 00 33 00 33 }
		$s1 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 31 00 2C 00 34 00 2C 00 33 00 2C 00 33 }

	condition:
		uint16(0)==0x5a4d and filesize <90KB and all of them
}
