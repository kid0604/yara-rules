import "pe"

rule NJoiner01AsmVersionNEX
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NJoiner01 malware based on the ASM version"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6A 00 68 00 14 40 00 68 00 10 40 00 6A 00 E8 14 00 00 00 6A 00 E8 13 00 00 00 CC FF 25 AC 12 40 00 FF 25 B0 12 40 00 FF 25 B4 12 40 00 FF 25 B8 12 40 00 FF 25 BC 12 40 00 FF 25 C0 12 40 00 FF 25 C4 12 40 00 FF 25 C8 12 40 00 FF 25 CC 12 40 00 FF 25 D0 12 40 00 FF 25 D4 12 40 00 FF 25 D8 12 40 00 FF 25 DC 12 40 00 FF 25 E4 12 40 00 FF 25 EC 12 40 00 }

	condition:
		$a0 at pe.entry_point
}
