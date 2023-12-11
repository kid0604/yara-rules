import "pe"

rule ExeToolsv21EncruptorbyDISMEMBER
{
	meta:
		author = "malware-lu"
		description = "Detects ExeToolsv21EncruptorbyDISMEMBER malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5D 83 [2] 1E 8C DA 83 [2] 8E DA 8E C2 BB [2] BA [2] 85 D2 74 }

	condition:
		$a0 at pe.entry_point
}
