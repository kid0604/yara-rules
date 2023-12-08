import "pe"

rule PolyEnEV001LennartHedlund
{
	meta:
		author = "malware-lu"
		description = "Detects a specific string in a file, possibly indicating the presence of the PolyEn malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 6F 6C 79 45 6E 45 00 4D 65 73 73 61 67 65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C }

	condition:
		$a0
}
