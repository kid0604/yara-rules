import "pe"

rule EmbedPEv124cyclotron
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of embedded PE file using specific byte sequence at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 50 60 68 [4] E8 CB FF 00 00 }

	condition:
		$a0 at pe.entry_point
}
