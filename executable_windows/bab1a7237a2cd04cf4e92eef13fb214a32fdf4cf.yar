import "pe"

rule MALWARE_Win_Neshta
{
	meta:
		author = "ditekSHen"
		description = "Detects Neshta"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus." fullword ascii
		$s2 = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
