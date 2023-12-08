rule Dos_Down64
{
	meta:
		description = "Chinese Hacktool Set - file Down64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "43e455e43b49b953e17a5b885ffdcdf8b6b23226"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Windows\\Temp\\Down.txt" fullword wide
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s3 = "C:\\Windows\\Temp\\" fullword wide
		$s4 = "ProcessXElement" fullword ascii
		$s8 = "down.exe" fullword wide
		$s20 = "set_Timer1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <150KB and all of them
}
