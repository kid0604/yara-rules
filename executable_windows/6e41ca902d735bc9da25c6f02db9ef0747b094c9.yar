import "pe"

rule MAL_BurningUmbrella_Sample_8
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "73270fe9bca94fead1b5b38ddf69fae6a42e574e3150d3e3ab369f5d37d93d88"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd /c open %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of them
}
