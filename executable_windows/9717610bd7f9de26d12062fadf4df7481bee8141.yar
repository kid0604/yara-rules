import "pe"

rule EmbedPEv113cyclotron
{
	meta:
		author = "malware-lu"
		description = "Detects the embedding of a PE file in the Cyclotron malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 }

	condition:
		$a0 at pe.entry_point
}
