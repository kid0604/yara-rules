import "pe"

rule CrackStopv101cStefanEsser1997
{
	meta:
		author = "malware-lu"
		description = "Detects CrackStop v1.01c by Stefan Esser (1997)"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC }

	condition:
		$a0 at pe.entry_point
}
