import "pe"

rule NETexecutableMicrosoft
{
	meta:
		author = "malware-lu"
		description = "Detects Microsoft .NET executable files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 00 00 00 FF 25 }

	condition:
		$a0
}
