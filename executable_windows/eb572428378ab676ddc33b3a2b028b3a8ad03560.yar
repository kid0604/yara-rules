import "pe"

rule Equation_Kaspersky_FannyWorm
{
	meta:
		description = "Equation Group Malware - Fanny Worm"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "1f0ae54ac3f10d533013f74f48849de4e65817a7"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$s1 = "x:\\fanny.bmp" fullword ascii
		$s2 = "32.exe" fullword ascii
		$s3 = "d:\\fanny.bmp" fullword ascii
		$x1 = "c:\\windows\\system32\\kernel32.dll" fullword ascii
		$x2 = "System\\CurrentControlSet\\Services\\USBSTOR\\Enum" fullword ascii
		$x3 = "System\\CurrentControlSet\\Services\\PartMgr\\Enum" fullword ascii
		$x4 = "\\system32\\win32k.sys" fullword wide
		$x5 = "\\AGENTCPD.DLL" fullword ascii
		$x6 = "agentcpd.dll" fullword ascii
		$x7 = "PADupdate.exe" fullword ascii
		$x8 = "dll_installer.dll" fullword ascii
		$x9 = "\\restore\\" fullword ascii
		$x10 = "Q:\\__?__.lnk" fullword ascii
		$x11 = "Software\\Microsoft\\MSNetMng" fullword ascii
		$x12 = "\\shelldoc.dll" fullword ascii
		$x13 = "file size = %d bytes" fullword ascii
		$x14 = "\\MSAgent" fullword ascii
		$x15 = "Global\\RPCMutex" fullword ascii
		$x16 = "Global\\DirectMarketing" fullword ascii

	condition:
		($mz at 0) and filesize <300000 and ((2 of ($s*)) or (1 of ($s*) and 6 of ($x*)) or (14 of ($x*)))
}
