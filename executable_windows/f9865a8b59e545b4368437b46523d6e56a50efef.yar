import "pe"

rule MAL_BurningUmbrella_Sample_16
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "58bb3859e02b8483e9f84cc56fbd964486e056ef28e94dd0027d361383cc4f4a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "http://netimo.net 0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
