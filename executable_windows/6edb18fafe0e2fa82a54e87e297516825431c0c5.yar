import "pe"

rule RLPackV112V114aPlib043ap0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack version 1.12 or 1.14a with PLib 0.43a"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF EB 0F FF [3] FF [3] D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB }

	condition:
		$a0
}
