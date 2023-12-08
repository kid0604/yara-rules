rule IDTools_For_WinXP_IdtTool_2
{
	meta:
		description = "Chinese Hacktool Set - file IdtTool.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "07feb31dd21d6f97614118b8a0adf231f8541a67"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\Device\\devIdtTool" fullword wide
		$s1 = "IoDeleteSymbolicLink" fullword ascii
		$s3 = "IoDeleteDevice" fullword ascii
		$s6 = "IoCreateSymbolicLink" fullword ascii
		$s7 = "IoCreateDevice" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <7KB and all of them
}
