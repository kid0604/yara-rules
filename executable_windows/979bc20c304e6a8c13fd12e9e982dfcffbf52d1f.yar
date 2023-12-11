import "pe"

rule EmbedPEV1Xcyclotron
{
	meta:
		author = "malware-lu"
		description = "Detects embedded PE file using specific entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 50 60 68 [4] E8 [2] 00 00 }

	condition:
		$a0 at pe.entry_point
}
