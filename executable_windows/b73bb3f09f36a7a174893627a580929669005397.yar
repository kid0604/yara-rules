import "pe"

rule MAL_BurningUmbrella_Sample_10
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "70992a72412c5d62d003a29c3967fcb0687189d3290ebbc8671fa630829f6694"
		hash2 = "48f0bbc3b679aac6b1a71c06f19bb182123e74df8bb0b6b04ebe99100c57a41e"
		hash3 = "5475ae24c4eeadcbd49fcd891ce64d0fe5d9738f1c10ba2ac7e6235da97d3926"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "revjj.syshell.org" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
