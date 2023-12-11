import "pe"

rule SimpleUPXCryptorv3042005multilayerencryptionMANtiCORE
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting SimpleUPXCryptorv3042005multilayerencryptionMANtiCORE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 B8 [3] 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 [3] 00 C3 }
		$a1 = { 60 B8 [4] B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 [4] C3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
