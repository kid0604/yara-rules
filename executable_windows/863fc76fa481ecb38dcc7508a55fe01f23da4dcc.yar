import "pe"

rule ExeJoinerV10Yodaf2f
{
	meta:
		author = "malware-lu"
		description = "Detects the ExeJoinerV10Yodaf2f malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 }

	condition:
		$a0 at pe.entry_point
}
