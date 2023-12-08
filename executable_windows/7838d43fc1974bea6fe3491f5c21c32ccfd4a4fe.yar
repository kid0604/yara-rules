rule Pc_pc2015
{
	meta:
		description = "Chinese Hacktool Set - file pc2015.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "de4f098611ac9eece91b079050b2d0b23afe0bcb"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
		$s8 = "%s%08x.001" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <309KB and all of them
}
