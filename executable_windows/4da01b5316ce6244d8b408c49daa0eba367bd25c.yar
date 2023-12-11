import "pe"

rule tElockv098
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElockv098 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 [4] 1E }

	condition:
		$a0 at pe.entry_point
}
