import "pe"

rule PolyCryptPE214b215JLabSoftwareCreationshsigned
{
	meta:
		author = "malware-lu"
		description = "Detects PolyCryptPE214b215JLabSoftwareCreationshsigned malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45 }

	condition:
		$a0
}
