import "pe"

rule ACProtectv190gRiscosoftwareInc
{
	meta:
		author = "malware-lu"
		description = "Detects ACProtect v1.90g by Risco software Inc"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3 }

	condition:
		$a0 at pe.entry_point
}
