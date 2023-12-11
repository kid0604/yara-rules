import "pe"

rule TPACKv05cm2
{
	meta:
		author = "malware-lu"
		description = "Detects TPACKv05cm2 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [2] FD 60 BE [2] BF [2] B9 [2] F3 A4 8B F7 BF [2] FC 46 E9 CE FD }

	condition:
		$a0 at pe.entry_point
}
