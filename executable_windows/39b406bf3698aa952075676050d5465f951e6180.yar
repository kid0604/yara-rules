import "pe"

rule DingBoysPElockv007
{
	meta:
		author = "malware-lu"
		description = "Detects DingBoysPElockv007 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00 }

	condition:
		$a0 at pe.entry_point
}
