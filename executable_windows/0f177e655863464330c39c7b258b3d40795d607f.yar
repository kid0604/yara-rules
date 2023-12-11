rule superscan3_0
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file superscan3.0.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a9a02a14ea4e78af30b8b4a7e1c6ed500a36bc4d"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\scanner.ini" fullword ascii
		$s1 = "\\scanner.exe" fullword ascii
		$s2 = "\\scanner.lst" fullword ascii
		$s4 = "\\hensss.lst" fullword ascii
		$s5 = "STUB32.EXE" fullword wide
		$s6 = "STUB.EXE" fullword wide
		$s8 = "\\ws2check.exe" fullword ascii
		$s9 = "\\trojans.lst" fullword ascii
		$s10 = "1996 InstallShield Software Corporation" fullword wide

	condition:
		all of them
}
