import "pe"

rule WWPACKv302v302aExtractable
{
	meta:
		author = "malware-lu"
		description = "Detects the WWPACKv302v302aExtractable malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 33 C9 B1 ?? 51 06 06 BB [2] 53 8C D3 }

	condition:
		$a0 at pe.entry_point
}
