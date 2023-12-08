import "pe"

rule ACProtect109gRiscosoftwareInc
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting ACProtect 1.09g Riscosoftware Inc malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00 }

	condition:
		$a0 at pe.entry_point
}
