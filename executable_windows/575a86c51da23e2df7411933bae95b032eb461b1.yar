import "pe"

rule LOCK98V10028keenvim
{
	meta:
		author = "malware-lu"
		description = "Detects LOCK98V10028keenvim malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 E8 00 00 00 00 5D 81 [5] EB 05 E9 [4] EB 08 }

	condition:
		$a0 at pe.entry_point
}
