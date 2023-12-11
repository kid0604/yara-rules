import "pe"

rule UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser
{
	meta:
		author = "malware-lu"
		description = "Detects the UPX version 2.00 - 2.90 by Markus Oberhumer, Laszlo Molnar, and John Reiser"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FF D5 8D 87 [4] 80 20 ?? 80 60 [2] 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
		$a0
}
