rule CobaltStrike_Resources_Httpstager_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager.bin signature for versions 2.5 to 4.x"
		hash = "a47569af239af092880751d5e7b68d0d8636d9f678f749056e702c9b063df256"
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
		$downloaderLoop = {
			B? 00 2F 00 00 
			39 ?? 
			74 ?? 
			31 ?? 
			( E9 | EB )
		}

	condition:
		$apiLocator and $downloaderLoop
}
