import "pe"

rule PseudoSigner02PEProtect09Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner02 PE Protect 09 Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 }

	condition:
		$a0 at pe.entry_point
}
