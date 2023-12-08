import "pe"

rule ACProtectv141
{
	meta:
		author = "malware-lu"
		description = "Detects ACProtect v1.41 protected files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 76 03 77 01 7B 74 03 75 01 78 47 87 EE E8 01 00 00 00 76 83 C4 04 85 EE EB 01 7F 85 F2 EB 01 79 0F 86 01 00 00 00 FC EB 01 78 79 02 87 F2 61 51 8F 05 19 38 01 01 60 EB 01 E9 E9 01 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
