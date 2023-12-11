import "pe"

rule ASProtectv12x_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect v1.2x alternate version 1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 68 01 [3] C3 AA }

	condition:
		$a0 at pe.entry_point
}
