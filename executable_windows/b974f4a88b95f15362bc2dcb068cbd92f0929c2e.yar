import "pe"

rule StarForceProtectionDriverProtectionTechnology
{
	meta:
		author = "malware-lu"
		description = "Detects StarForce Protection Driver Protection Technology"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 57 68 ?? 0D 01 00 68 00 [2] 00 E8 50 ?? FF FF 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 }

	condition:
		$a0 at pe.entry_point
}
