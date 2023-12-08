rule CobaltStrike_Resources_Bind_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bind.bin signature for versions 2.5 to 4.x"
		hash = "3727542c0e3c2bf35cacc9e023d1b2d4a1e9e86ee5c62ee5b66184f46ca126d1"
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
		$listenaccept = {
			5? 
			5? 
			68 B7 E9 38 FF
			FF ?? 
			5? 
			5? 
			5? 
			68 74 EC 3B E1
		}

	condition:
		$apiLocator and $ws2_32 and $listenaccept
}
