rule GoodToolset_ms11011
{
	meta:
		description = "Chinese Hacktool Set - file ms11011.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s3 = "Not supported." fullword wide
		$s4 = "SystemDefaultEUDCFont" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
