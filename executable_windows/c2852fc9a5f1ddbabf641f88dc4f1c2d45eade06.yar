import "pe"

rule MAL_BurningUmbrella_Sample_3
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "92efbecc24fbb5690708926b6221b241b10bdfe3dd0375d663b051283d0de30f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "HKEY_CLASSES_ROOT\\Word.Document.8\\shell\\Open\\command" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of them
}
