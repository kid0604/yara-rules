import "pe"

rule WiltedTulip_Tools_back
{
	meta:
		description = "Detects Chrome password dumper used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		modified = "2022-12-21"
		hash1 = "b7faeaa6163e05ad33b310a8fdc696ccf1660c425fa2a962c3909eada5f2c265"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%s.exe -f \"C:\\Users\\Admin\\Google\\Chrome\\TestProfile\" -o \"c:\\passlist.txt\"" fullword ascii
		$x2 = "\\ChromePasswordDump\\Release\\FireMaster.pdb" ascii
		$x3 = "//Dump Chrome Passwords to a Output file \"c:\\passlist.txt\"" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of them )
}
