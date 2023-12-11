import "pe"

rule PeStubOEPv1x
{
	meta:
		author = "malware-lu"
		description = "Detects PE files with specific entry point stub code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 33 C9 33 D2 B8 [3] 00 B9 FF }
		$a1 = { E8 05 00 00 00 33 C0 40 48 C3 E8 05 }

	condition:
		$a0 or $a1
}
