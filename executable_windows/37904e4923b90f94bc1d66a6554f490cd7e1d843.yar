rule CobaltStrike_Resources_Httpsstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpsstager.bin signature for versions 2.5 to 4.x"
		hash = "5ebe813a4c899b037ac0ee0962a439833964a7459b7a70f275ac73ea475705b3"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$apiLocator = {
			31 ?? 
			AC
			C1 ?? 0D 
			01 ?? 
			38 ?? 
			75 ?? 
			03 [2]
			3B [2]
			75 ?? 
			5? 
			8B ?? 24 
			01 ?? 
			66 8B [2]
			8B ?? 1C 
			01 ?? 
			8B ?? 8B 
			01 ?? 
			89 [3]
			5? 
			5? 
		}
		$InternetSetOptionA = {
			6A 04
			5? 
			6A 1F
			5? 
			68 75 46 9E 86
			FF  
		}

	condition:
		$apiLocator and $InternetSetOptionA
}
