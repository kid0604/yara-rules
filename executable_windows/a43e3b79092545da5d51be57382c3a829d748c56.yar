import "pe"

rule eXPressorProtection150XCGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressor protection used by XCGSoftLabs"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 68 EB 01 [4] 83 EC 0C 53 56 57 EB 01 ?? 83 3D [4] 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02 E8 E9 C7 05 [4] 01 00 00 00 EB 01 C2 E8 E2 05 00 00 EB 02 DA 9F 68 [4] 68 [4] B8 [4] FF D0 59 59 EB 01 C8 EB 02 66 F0 68 [4] E8 0E 05 00 00 59 EB 01 DD 83 65 F4 00 EB 07 8B 45 F4 40 89 45 F4 83 7D F4 61 73 1F EB 02 DA 1A 8B 45 F4 0F [6] 33 45 F4 8B 4D F4 88 [5] EB 01 EB EB }

	condition:
		$a0
}
