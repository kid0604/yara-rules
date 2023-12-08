import "pe"

rule ASProtectv123RC1
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect v1.23 RC1 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 01 [2] 00 E8 01 00 00 00 C3 C3 }

	condition:
		$a0 at pe.entry_point
}
