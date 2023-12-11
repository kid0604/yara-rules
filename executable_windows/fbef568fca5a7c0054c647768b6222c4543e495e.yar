rule CobaltStrike_Resources_Reverse64_Bin_v2_5_through_v4_x
{
	meta:
		description = "Cobalt Strike's resources/reverse64.bin signature for versions v2.5 to v4.x"
		hash = "d2958138c1b7ef681a63865ec4a57b0c75cc76896bf87b21c415b7ec860397e8"
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
		$calls = {
			48 89 C1
			41 BA EA 0F DF E0
			FF D5
			48 [2]
			6A ??
			41 ??
			4C [2]
			48 [2]
			41 BA 99 A5 74 61
			FF D5
		}

	condition:
		$apiLocator and $calls
}
