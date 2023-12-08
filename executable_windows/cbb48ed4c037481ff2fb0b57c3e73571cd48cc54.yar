import "pe"

rule ASProtectv11
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect v1.1 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E9 ?? 04 [2] E9 [7] EE }

	condition:
		$a0 at pe.entry_point
}
