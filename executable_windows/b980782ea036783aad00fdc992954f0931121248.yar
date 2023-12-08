import "pe"

rule Tiny_Network_Tool_Generic_alt_1 : FILE
{
	meta:
		description = "Tiny tool with suspicious function imports. (Rule based on WinEggDrop Scanner samples)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "08.10.2014"
		score = 40
		hash0 = "9e1ab25a937f39ed8b031cd8cfbc4c07"
		hash1 = "cafc31d39c1e4721af3ba519759884b9"
		hash2 = "8e635b9a1e5aa5ef84bfa619bd2a1f92"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "KERNEL32.DLL" fullword ascii
		$s1 = "CRTDLL.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii
		$y1 = "WININET.DLL" fullword ascii
		$y2 = "atoi" fullword ascii
		$x1 = "ADVAPI32.DLL" fullword ascii
		$x2 = "USER32.DLL" fullword ascii
		$x3 = "wsock32.dll" fullword ascii
		$x4 = "FreeSid" fullword ascii
		$x5 = "atoi" fullword ascii
		$z1 = "ADVAPI32.DLL" fullword ascii
		$z2 = "USER32.DLL" fullword ascii
		$z3 = "FreeSid" fullword ascii
		$z4 = "ToAscii" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of ($s*) and ( all of ($y*) or all of ($x*) or all of ($z*)) and filesize <15KB
}
