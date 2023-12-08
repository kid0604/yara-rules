import "pe"

rule Trivial173bySMTSMF
{
	meta:
		author = "malware-lu"
		description = "Detects Trivial173 malware by SMTSMF"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB [2] 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29 }

	condition:
		$a0 at pe.entry_point
}
