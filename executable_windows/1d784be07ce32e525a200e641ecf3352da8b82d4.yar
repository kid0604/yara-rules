import "pe"

rule VxHorse1776
{
	meta:
		author = "malware-lu"
		description = "Detects VxHorse1776 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5D 83 [2] 06 1E 26 [4] BF [2] 1E 0E 1F 8B F7 01 EE B9 [2] FC F3 A6 1F 1E 07 }

	condition:
		$a0 at pe.entry_point
}
