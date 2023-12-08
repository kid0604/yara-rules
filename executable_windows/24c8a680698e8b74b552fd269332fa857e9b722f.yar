import "pe"

rule ASProtectv20
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect v2.0 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }

	condition:
		$a0
}
