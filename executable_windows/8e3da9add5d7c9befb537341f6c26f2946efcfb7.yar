import "pe"

rule PasswordProtectorcMiniSoft1992
{
	meta:
		author = "malware-lu"
		description = "Detects PasswordProtectorcMiniSoft1992 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA }

	condition:
		$a0 at pe.entry_point
}
