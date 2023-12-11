import "pe"

rule InstallAnywhere61ZeroGSoftwareInc
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting InstallAnywhere 6.1 ZeroG Software Inc"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
		$a1 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
