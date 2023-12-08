import "pe"

rule Splasherv10v30
{
	meta:
		author = "malware-lu"
		description = "Detects Splasher v1.0 and v3.0 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 8B 44 24 24 E8 [4] 5D 81 ED [4] 50 E8 ED 02 [2] 8C C0 0F 84 }

	condition:
		$a0 at pe.entry_point
}
