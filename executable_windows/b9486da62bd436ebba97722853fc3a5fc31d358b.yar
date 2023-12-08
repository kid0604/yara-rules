import "pe"

rule Armadillo430aSiliconRealmsToolworks
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo430aSiliconRealmsToolworks malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 27 20 61 6E 64 20 27 25 73 27 00 00 00 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 55 4E 49 43 }

	condition:
		$a0
}
