import "pe"

rule ExeShieldv29
{
	meta:
		author = "malware-lu"
		description = "Detects ExeShield v2.9 protected executables"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC [3] F8 }

	condition:
		$a0 at pe.entry_point
}
