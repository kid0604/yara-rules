import "pe"

rule MAL_BurningUmbrella_Sample_11
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "278e9d130678615d0fee4d7dd432f0dda6d52b0719649ee58cbdca097e997c3f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Resume.app/Contents/Java/Resume.jarPK" fullword ascii

	condition:
		uint16(0)==0x4b50 and filesize <700KB and 1 of them
}
