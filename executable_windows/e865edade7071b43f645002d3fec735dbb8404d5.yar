import "pe"

rule UPXV194MarkusOberhumerLaszloMolnarJohnReiser
{
	meta:
		author = "malware-lu"
		description = "Detects the UPXv1.94 Markus Oberhumer, Laszlo Molnar, John Reiser packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FF D5 80 A7 [5] 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
		$a0
}
