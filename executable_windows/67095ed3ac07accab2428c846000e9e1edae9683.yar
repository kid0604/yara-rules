import "pe"

rule PCShrinkv040b
{
	meta:
		author = "malware-lu"
		description = "Detects PCShrinkv040b malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 BD [4] 01 [5] FF [5] 6A ?? FF [5] 50 50 2D }

	condition:
		$a0 at pe.entry_point
}
