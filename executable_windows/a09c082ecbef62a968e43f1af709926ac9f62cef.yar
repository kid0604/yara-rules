import "pe"

rule PCShrinkerv071
{
	meta:
		author = "malware-lu"
		description = "Detects PCShrinker v0.71 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 BD [4] 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D [4] 89 85 }

	condition:
		$a0 at pe.entry_point
}
