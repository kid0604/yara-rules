rule CobaltStrike_Resources_Httpstager64_Bin_v3_2_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/httpstager64.bin signature for versions v3.2 to v4.x"
		hash = "ad93d1ee561bc25be4a96652942f698eac9b133d8b35ab7e7d3489a25f1d1e76"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$apiLocator = {
			48 [2]
			AC
			41 [2] 0D
			41 [2]
			38 ??
			75 ??
			4C [4]
			45 [2]
			75 ??
			5?
			44 [2] 24
			49 [2]
			66 [4]
			44 [2] 1C
			49 [2]
			41 [3]
			48 
		}
		$postInternetOpenJmp = {
			41 ?? 3A 56 79 A7
			FF ??
			EB 
		}

	condition:
		$apiLocator and $postInternetOpenJmp
}
