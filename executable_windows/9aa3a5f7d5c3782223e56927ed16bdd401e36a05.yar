rule CN_Hacktool_S_EXE_Portscanner
{
	meta:
		description = "Detects a chinese Portscanner named s.exe"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\Result.txt" fullword ascii
		$s1 = "By:ZT QQ:376789051" fullword ascii
		$s2 = "(http://www.eyuyan.com)" fullword wide

	condition:
		all of them
}
