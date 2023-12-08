import "pe"

rule CopyMinderMicrocosmLtd
{
	meta:
		author = "malware-lu"
		description = "Detects CopyMinderMicrocosmLtd malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 25 [4] EF 6A 00 E8 [4] E8 [4] CC FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 }

	condition:
		$a0 at pe.entry_point
}
