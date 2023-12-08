rule CobaltStrike_Resources_Elevate_X64_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_X64_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.x64.dll signature for v3.0 to v3.14 and sleeve/elevate.x64.dll for v4.x"
		hash = "c3ee8a9181fed39cec3bd645b32b611ce98d2e84c5a9eff31a8acfd9c26410ec"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$wnd_proc = {
			81 ?? 21 01 00 00
			75 ??
			83 [5] 00
			75 ??
			45 33 ??
			8D [2]
			C7 [5] 01 00 00 00
			45 [2] 28
			FF 15 [4]
			45 33 ??
			8D [2]
			45 [2] 27
			48 [2]
			FF 15 [4]
			45 33 ??
			45 33 ??
			BA 01 02 00 00
			48 
		}

	condition:
		$wnd_proc
}
