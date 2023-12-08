import "pe"

rule bambam004bedrock
{
	meta:
		author = "malware-lu"
		description = "Detects the Bambam004bedrock malware based on its entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BF [4] 83 C9 FF 33 C0 68 [4] F2 AE F7 D1 49 51 68 [4] E8 11 0A 00 00 83 C4 0C 68 [4] FF 15 [4] 8B F0 BF [4] 83 C9 FF 33 C0 F2 AE F7 D1 49 BF [4] 8B D1 68 [4] C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF [4] 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 [4] E8 C0 09 00 00 }

	condition:
		$a0 at pe.entry_point
}
