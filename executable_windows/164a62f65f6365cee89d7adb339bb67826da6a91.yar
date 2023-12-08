import "math"
import "pe"

rule Mimikatz_Memory_Rule_2_alt_1
{
	meta:
		description = "Detect the risk of Malware Mimikatz Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "sekurlsa::" ascii
		$x1 = "cryptprimitives.pdb" ascii
		$x2 = "Now is t1O" ascii fullword
		$x4 = "ALICE123" ascii
		$x5 = "BOBBY456" ascii

	condition:
		$s0 and 2 of ($x*)
}
