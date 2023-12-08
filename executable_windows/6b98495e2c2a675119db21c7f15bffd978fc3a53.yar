import "pe"

rule ASProtectv10
{
	meta:
		author = "malware-lu"
		description = "Detects ASProtect v1.0 protected files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 01 [3] 90 5D 81 ED [4] BB [4] 03 DD 2B 9D }

	condition:
		$a0 at pe.entry_point
}
