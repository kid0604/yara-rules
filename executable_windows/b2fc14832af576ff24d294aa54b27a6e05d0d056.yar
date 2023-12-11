import "pe"

rule DIETv102bv110av120
{
	meta:
		author = "malware-lu"
		description = "Detects DIETv102bv110av120 malware based on entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [2] BF [2] B9 [2] 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC }

	condition:
		$a0 at pe.entry_point
}
