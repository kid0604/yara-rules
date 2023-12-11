import "pe"

rule PseudoSigner02PEIntro10Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02 PE Intro 10 Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A }

	condition:
		$a0 at pe.entry_point
}
