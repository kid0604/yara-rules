import "pe"

rule SmokesCryptv12
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of SmokesCryptv12 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 B8 [4] B8 [4] 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }

	condition:
		$a0 at pe.entry_point
}
