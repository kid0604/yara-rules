import "pe"

rule CDCopsII_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects CDCopsII malware variant 1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 60 BD [4] 8D 45 ?? 8D 5D ?? E8 [4] 8D }

	condition:
		$a0 at pe.entry_point
}
