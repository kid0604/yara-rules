rule CobaltStrike_Resources_Xor_Bin__64bit_v3_12_to_v4_x
{
	meta:
		description = "Cobalt Strike's resource/xor64.bin signature for version 3.12 through 4.x"
		hash = "01dba8783768093b9a34a1ea2a20f72f29fd9f43183f3719873df5827a04b744"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$stub58 = {fc e8 ?? ?? ?? ?? [1-32] eb 33 5? 8b ?? 00 4? 83 ?? ?4 8b ?? 00 31 ?? 4? 83 ?? ?4 5? 8b ?? 00 31 ?? 89 ?? 00 31 ?? 4? 83 ?? ?4 83 ?? ?4 31 ?? 39 ?? 74 ?2 eb e7 5? fc 4? 83 ?? f0 ff}
		$stub59 = {fc e8 ?? ?? ?? ?? [1-32] eb 2e 5? 8b ??    48 83 c? ?4 8b ??    31 ?? 48 83 c? ?4 5? 8b ??    31 ?? 89 ??    31 ?? 48 83 c? ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e9 5?    48 83 ec ?8 ff e? e8 cd ff ff ff}
		$stub63 = {fc e8 ?? ?? ?? ?? [1-32] eb 32 5d 8b ?? ?? 48 83 c5 ?4 8b ?? ?? 31 ?? 48 83 c5 ?4 55 8b ?? ?? 31 ?? 89 ?? ?? 31 ?? 48 83 c5 ?4 83 e? ?4 31 ?? 39 ?? 74 ?2 eb e7 5?    48 83 ec ?8 ff e? e8 c9 ff ff ff}

	condition:
		any of them
}
