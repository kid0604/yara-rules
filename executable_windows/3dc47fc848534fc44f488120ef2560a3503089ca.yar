import "pe"

rule RosAsm2050aBetov
{
	meta:
		author = "malware-lu"
		description = "Detects the RosAsm2050aBetov malware based on specific byte patterns"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 60 8B 5D 08 B9 08 00 00 00 BF [4] 83 C7 07 FD 8A C3 24 0F 04 30 3C 39 76 02 04 07 AA C1 EB 04 E2 EE FC 68 00 10 00 00 68 [4] 68 [4] 6A 00 FF 15 [4] 61 8B E5 5D C2 04 00 }

	condition:
		$a0
}
