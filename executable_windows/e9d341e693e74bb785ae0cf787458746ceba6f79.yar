import "pe"

rule IMPPacker10MahdiHezavehiIMPOSTER
{
	meta:
		author = "malware-lu"
		description = "Detects the IMPOSTER packer version 1.0 by Mahdi Hezavehi"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 28 [3] 00 00 00 00 00 00 00 00 40 [3] 34 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C [3] 5C [3] 00 00 00 00 [8] 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 }

	condition:
		$a0
}
