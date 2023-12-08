import "pe"

rule PEPaCKv10CCopyright1998byANAKiN
{
	meta:
		author = "malware-lu"
		description = "Detects PEPaCKv10CCopyright1998byANAKiN malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 2D 3D FE 20 50 45 2D 50 41 43 4B 20 76 31 2E 30 20 2D FE 2D 20 28 43 29 20 43 6F 70 }

	condition:
		$a0
}
