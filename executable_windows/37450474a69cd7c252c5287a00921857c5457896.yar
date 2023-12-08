import "pe"

rule PseudoSigner02VBOX43MTEAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, potentially indicating a pseudo signer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }

	condition:
		$a0 at pe.entry_point
}
