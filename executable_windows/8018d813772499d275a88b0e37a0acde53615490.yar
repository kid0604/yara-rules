import "pe"

rule ASProtectv11MTEc
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect v1.1 MTEc packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 60 E8 1B [3] E9 FC }

	condition:
		$a0 at pe.entry_point
}
