import "pe"

rule hmimysPackerV12hmimys
{
	meta:
		author = "malware-lu"
		description = "Detects hmimys Packer V12"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 95 00 00 00 [149] 5E AD 50 AD 50 97 AD 50 AD 50 AD 50 E8 C0 01 00 00 AD 50 AD 93 87 DE B9 [4] E3 1D 8A 07 47 04 ?? 3C ?? 73 F7 8B 07 3C ?? 75 F3 B0 00 0F C8 05 [4] 2B C7 AB E2 E3 AD 85 C0 74 2B 97 56 FF 13 8B E8 AC 84 C0 75 FB 66 AD 66 85 C0 74 E9 AC 83 EE 03 84 C0 74 08 56 55 FF 53 04 AB EB E4 AD 50 55 FF 53 04 AB EB E0 C3 8B 0A 3B 4A 04 75 0A C7 42 10 01 00 00 00 0C FF C3 }

	condition:
		$a0 at pe.entry_point
}
