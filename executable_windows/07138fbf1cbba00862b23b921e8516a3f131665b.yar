rule SQLCracker
{
	meta:
		description = "Chinese Hacktool Set - file SQLCracker.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "msvbvm60.dll" fullword ascii
		$s1 = "_CIcos" fullword ascii
		$s2 = "kernel32.dll" fullword ascii
		$s3 = "cKmhV" fullword ascii
		$s4 = "080404B0" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <125KB and all of them
}
