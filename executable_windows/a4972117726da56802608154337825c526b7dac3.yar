import "pe"

rule RUAG_APT_Malware_Gen2
{
	meta:
		description = "Detects malware used in the RUAG APT case"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		modified = "2023-01-06"
		score = 90
		hash1 = "0e1bf347c37fb199886f1e675e372ba55ac4627e8be2f05a76c2c64f9b6ed0e4"
		hash2 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash3 = "fe3ffd7438c0d38484bf02a78a19ea81a6f51b4b3f2b2228bd21974c2538bbcd"
		hash4 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Internal command not support =((" ascii
		$x2 = "L|-1|AS_CUR_USER:OpenProcessToken():%d, %s|" fullword ascii
		$x3 = "L|-1|CreateProcessAsUser():%d, %s|" fullword ascii
		$x4 = "AS_CUR_USER:OpenProcessToken():%d" fullword ascii
		$x5 = "L|-1|AS_CUR_USER:LogonUser():%d, %s|" fullword ascii
		$x6 = "L|-1|try to run dll %s with user priv|" fullword ascii
		$x7 = "\\\\.\\Global\\PIPE\\sdlrpc" fullword ascii
		$x8 = "\\\\%s\\pipe\\comnode" fullword ascii
		$x9 = "Plugin dll stop failed." fullword ascii
		$x10 = "AS_USER:LogonUser():%d" fullword ascii
		$s1 = "MSIMGHLP.DLL" fullword wide
		$s2 = "msimghlp.dll" fullword ascii
		$s3 = "ximarsh.dll" fullword ascii
		$s4 = "msximl.dll" fullword ascii
		$s5 = "INTERNAL.dll" fullword ascii
		$s6 = "\\\\.\\Global\\PIPE\\" ascii
		$s7 = "ieuser.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) or 5 of ($s*))) or (10 of them )
}
