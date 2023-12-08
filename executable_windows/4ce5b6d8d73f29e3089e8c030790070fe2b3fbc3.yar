rule HackingTeam_Elevator_EXE
{
	meta:
		description = "Hacking Team Disclosure Sample - file elevator.exe"
		author = "Florian Roth"
		reference = "Hacking Team Disclosure elevator.c"
		date = "2015-07-07"
		hash1 = "40a10420b9d49f87527bc0396b19ec29e55e9109e80b52456891243791671c1c"
		hash2 = "92aec56a859679917dffa44bd4ffeb5a8b2ee2894c689abbbcbe07842ec56b8d"
		hash = "9261693b67b6e379ad0e57598602712b8508998c0cb012ca23139212ae0009a1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "CRTDLL.DLL" fullword ascii
		$x2 = "\\sysnative\\CI.dll" fullword ascii
		$x3 = "\\SystemRoot\\system32\\CI.dll" fullword ascii
		$x4 = "C:\\\\Windows\\\\Sysnative\\\\ntoskrnl.exe" fullword ascii
		$s1 = "[*] traversing processes" fullword ascii
		$s2 = "_getkprocess" fullword ascii
		$s3 = "[*] LoaderConfig %p" fullword ascii
		$s4 = "loader.obj" fullword ascii
		$s5 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3" ascii
		$s6 = "[*] token restore" fullword ascii
		$s7 = "elevator.obj" fullword ascii
		$s8 = "_getexport" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of ($x*) and 3 of ($s*)
}
