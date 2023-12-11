import "pe"

rule MAL_BurningUmbrella_Sample_1
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "fcfe8fcf054bd8b19226d592617425e320e4a5bb4798807d6f067c39dfc6d1ff"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 40 00 00 E0 75 68 66 61 6F 68 6C 79 }
		$s2 = { 40 00 00 E0 64 6A 7A 66 63 6D 77 62 }

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and (pe.imphash()=="baa93d47220682c04d92f7797d9224ce" and $s1 in (0..1024) and $s2 in (0..1024))
}
