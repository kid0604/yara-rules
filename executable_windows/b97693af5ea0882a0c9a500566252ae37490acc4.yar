import "pe"

rule PseudoSigner01StelthPE101Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a stealth PE file with PseudoSigner01StelthPE101Anorganix signature"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA [4] FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
