rule CobaltStrike_Resources_Reverse_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse.bin signature for versions 2.5 to 4.x"
		hash = "887f666d6473058e1641c3ce1dd96e47189a59c3b0b85c8b8fccdd41b84000c7"
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
		$ws2_32 = {
			5D
			68 33 32 00 00
			68 77 73 32 5F
		}
		$connect = {
			6A 10
			5? 
			5? 
			68 99 A5 74 61
		}

	condition:
		$apiLocator and $ws2_32 and $connect
}
