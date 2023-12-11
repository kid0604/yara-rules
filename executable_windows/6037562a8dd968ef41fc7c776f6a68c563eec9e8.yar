import "pe"

rule PseudoSigner01XCR011Anorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01XCR011Anorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9 }

	condition:
		$a0 at pe.entry_point
}
