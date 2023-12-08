import "pe"

rule ThinstallV27XJitit
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall v2.7X Jitit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB [4] 2B C3 50 68 [4] 68 [4] 68 [4] E8 [4] E9 }

	condition:
		$a0 at pe.entry_point
}
