rule Mimikatz_Memory_Rule_2 : APT
{
	meta:
		description = "Mimikatz Rule generated from a memory dump"
		author = "Florian Roth - Florian Roth"
		type = "memory"
		score = 80
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "sekurlsa::" ascii
		$x1 = "cryptprimitives.pdb" ascii
		$x2 = "Now is t1O" ascii fullword
		$x4 = "ALICE123" ascii
		$x5 = "BOBBY456" ascii

	condition:
		$s0 and 1 of ($x*)
}
