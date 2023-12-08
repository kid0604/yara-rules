import "pe"

rule PECompactv25RetailSlimLoaderBitsumTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact v2.5 Retail SlimLoader by Bitsum Technologies"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [3] 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

	condition:
		$a0 at pe.entry_point
}
