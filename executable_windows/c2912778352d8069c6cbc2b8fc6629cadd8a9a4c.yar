rule CobaltStrike_Resources_Elevate_Dll_v3_0_to_v3_14_and_Sleeve_Elevate_Dll_v4_x
{
	meta:
		description = "Cobalt Strike's resources/elevate.dll signature for v3.0 to v3.14 and sleeve/elevate.dll for v4.x"
		hash = "6deeb2cafe9eeefe5fc5077e63cc08310f895e9d5d492c88c4e567323077aa2f"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$wnd_proc = {
			6A 00
			6A 28
			68 00 01 00 00
			5? 
			C7 [5] 01 00 00 00 
			FF ?? 
			6A 00
			6A 27
			68 00 01 00 00
			5? 
			FF ?? 
			6A 00
			6A 00
			68 01 02 00 00
			5? 
			FF ?? 
		}

	condition:
		$wnd_proc
}
