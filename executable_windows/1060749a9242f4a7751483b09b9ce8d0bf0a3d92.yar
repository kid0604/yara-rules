rule hscan_gui
{
	meta:
		description = "Chinese Hacktool Set - file hscan-gui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1885f0b7be87f51c304b39bc04b9423539825c69"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Hscan.EXE" fullword wide
		$s1 = "RestTool.EXE" fullword ascii
		$s3 = "Hscan Application " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <550KB and all of them
}
