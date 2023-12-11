import "pe"

rule CobaltGang_Malware_Aug17_2
{
	meta:
		description = "Detects a Cobalt Gang malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://sslbl.abuse.ch/intel/6ece5ece4192683d2d84e25b0ba7e04f9cb7eb7c"
		date = "2017-08-09"
		hash1 = "80791d5e76782cc3cd14f37f351e33b860818784192ab5b650f1cdf4f131cf72"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; BOIE9;ENGB)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <80KB and all of them )
}
