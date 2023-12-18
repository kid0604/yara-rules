import "pe"

rule INDICATOR_TOOLS_EDRSandBlast
{
	meta:
		author = "ditekShen"
		description = "Detects EDRSandBlast"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "credguard" fullword wide
		$s2 = "\\cmd.exe" fullword wide
		$s3 = "ci_%s.dll" fullword wide
		$s4 = "cmd /c sc" wide
		$s5 = "fltmgr_%s.sys" fullword wide
		$s6 = "ntoskrnl_%s.exe" fullword wide
		$s7 = "ProductDir" fullword wide
		$s8 = "lsass.exe" fullword wide
		$s9 = "0x%p;%ws;%ws;;;" ascii
		$s10 = "MiniDumpWriteDump" ascii
		$s11 = "EDRSB_Init: %u" ascii
		$s12 = "ntoskrnloffsets.csv" fullword wide nocase
		$s13 = "wdigestoffsets.csv" fullword wide nocase
		$o1 = { eb 0e 8b 85 34 15 00 00 ff c0 89 85 34 15 00 00 }
		$o2 = { 74 48 8b 85 34 15 00 00 41 b9 04 01 00 00 4c 8d }

	condition:
		uint16(0)==0x5a4d and 7 of them
}
