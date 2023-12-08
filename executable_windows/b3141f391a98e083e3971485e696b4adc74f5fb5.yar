import "pe"

rule PEtitev13
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PEtitev13 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 66 9C 60 50 8D 88 ?? F0 [2] 8D 90 04 16 [2] 8B DC 8B E1 68 [4] 53 50 80 04 24 08 50 80 04 24 42 }

	condition:
		$a0 at pe.entry_point
}
