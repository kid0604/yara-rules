import "pe"

rule WWPACKv300v301Relocationspack
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the WWPACK v3.00/v3.01 Relocations pack"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [2] BA [2] BF [2] B9 [2] 8C CD 8E DD 81 ED [2] 06 06 8B DD 2B DA 8B D3 FC }

	condition:
		$a0 at pe.entry_point
}
