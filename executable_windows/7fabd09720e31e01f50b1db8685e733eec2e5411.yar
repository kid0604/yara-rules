import "pe"

rule ASProtectv11MTE_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect v1.1 MTE packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E9 [4] 91 78 79 79 79 E9 }

	condition:
		$a0 at pe.entry_point
}
