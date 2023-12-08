import "pe"

rule EPWv130
{
	meta:
		author = "malware-lu"
		description = "Detects a specific entry point in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E }

	condition:
		$a0 at pe.entry_point
}
