import "pe"

rule MAL_BurningUmbrella_Sample_14
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "388ef4b4e12a04eab451bd6393860b8d12948f2bce12e5c9022996a9167f4972"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\tmp\\Google_updata.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and 1 of them
}
