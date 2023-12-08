import "pe"

rule PseudoSigner01CrunchPEHeuristicAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01Crunch PE Heuristic Anorganix"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD [4] 2B 85 00 00 00 00 E9 }

	condition:
		$a0 at pe.entry_point
}
