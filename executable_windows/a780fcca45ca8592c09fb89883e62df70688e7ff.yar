import "pe"

rule MAL_BurningUmbrella_Sample_19
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "05e2912f2a593ba16a5a094d319d96715cbecf025bf88bb0293caaf6beb8bc20"
		hash2 = "e7bbdb275773f43c8e0610ad75cfe48739e0a2414c948de66ce042016eae0b2e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Cryption.dll" fullword ascii
		$s2 = "tran.exe" fullword ascii
		$s3 = "Kernel.dll" fullword ascii
		$s4 = "Now ready to get the file %s!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 3 of them
}
