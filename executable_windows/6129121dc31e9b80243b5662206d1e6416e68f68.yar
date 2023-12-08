import "pe"

rule PseudoSigner01VBOX43MTEAnorganix
{
	meta:
		author = "malware-lu"
		description = "Detects PseudoSigner01VBOX43MTEAnorganix malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9 }

	condition:
		$a0 at pe.entry_point
}
