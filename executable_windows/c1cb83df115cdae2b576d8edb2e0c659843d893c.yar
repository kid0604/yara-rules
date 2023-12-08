import "pe"

rule MALWARE_Win_Klackring
{
	meta:
		author = "ditekSHen"
		description = "Detects Klackring variants. Associated with ZINC / Lazarus"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s\\%s.dll" fullword wide
		$s2 = "cmd.exe /c move /Y %s %s" fullword wide
		$s3 = "%s\\win32k.sys" fullword wide
		$s4 = "NetSvcInst_Rundll32.dll" fullword ascii
		$s5 = "Spectrum.dll" fullword ascii wide
		$s6 = "%s\\cmd.exe" fullword wide
		$s7 = ".?AVA5Stream@@" fullword ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}
