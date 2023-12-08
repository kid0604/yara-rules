import "pe"

rule NTPackerV2XErazerZ
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NTPackerV2XErazerZ malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 4B 57 69 6E 64 6F 77 73 00 10 55 54 79 70 65 73 00 00 3F 75 6E 74 4D 61 69 6E 46 75 6E 63 74 69 6F 6E 73 00 00 47 75 6E 74 42 79 70 61 73 73 00 00 B7 61 50 4C 69 62 75 00 00 00 }

	condition:
		$a0
}
