import "pe"

rule DragonArmorOrient
{
	meta:
		author = "malware-lu"
		description = "Detects DragonArmor malware based on specific byte patterns in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BF 4C [2] 00 83 C9 FF 33 C0 68 34 [2] 00 F2 AE F7 D1 49 51 68 4C [2] 00 E8 11 0A 00 00 83 C4 0C 68 4C [2] 00 FF 15 00 [2] 00 8B F0 BF 4C [2] 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 4C [2] 00 8B D1 68 34 [2] 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF 5C [2] 00 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 5C [2] 00 E8 C0 09 00 00 8B 1D 04 [2] 00 83 C4 0C 68 5C [2] 00 56 FF D3 A3 D4 [2] 00 BF 5C [2] 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 5C [2] 00 8B D1 68 34 [2] 00 C1 E9 02 F3 AB 8B CA 83 E1 }

	condition:
		$a0
}
