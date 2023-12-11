rule xdedic_packed_syscan_alt_1
{
	meta:
		author = "Kaspersky Lab - modified by Florian Roth"
		company = "Kaspersky Lab"
		description = "Detects the presence of the xdedic_packed_syscan_alt_1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "SysScan.exe" nocase ascii wide
		$a2 = "1.3.4." wide

	condition:
		uint16(0)==0x5A4D and filesize >500KB and filesize <1500KB and all of them
}
