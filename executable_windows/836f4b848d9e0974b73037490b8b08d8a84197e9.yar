import "pe"

rule PECompact2xxSlimLoaderBitSumTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact2xx SlimLoader BitSum Technologies"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

	condition:
		$a0 at pe.entry_point
}
