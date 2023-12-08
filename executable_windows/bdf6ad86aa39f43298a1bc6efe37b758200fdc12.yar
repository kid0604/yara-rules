rule Dos_Down32
{
	meta:
		description = "Chinese Hacktool Set - file Down32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365738acd728021b0ea2967c867f1014fd7dd75"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s6 = "down.exe" fullword wide
		$s15 = "get_Form1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <137KB and all of them
}
