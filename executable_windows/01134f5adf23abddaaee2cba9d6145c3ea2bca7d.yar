import "pe"

rule EXEJoinerv10
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of EXEJoiner v1.0 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 [4] 68 [4] 6A 00 E8 }

	condition:
		$a0 at pe.entry_point
}
