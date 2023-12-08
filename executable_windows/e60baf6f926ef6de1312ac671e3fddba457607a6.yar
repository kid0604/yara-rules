rule CobaltStrike_Resources_Bypassuac_x64_Dll_v3_3_to_v3_14_and_Sleeve_Bypassuac_x64_Dll_v4_0_and_v4_x
{
	meta:
		description = "Cobalt Strike's resources/bypassuac-x64.dll from v3.3 to v3.14 (64-bit version) and sleeve/bypassuac.x64.dll from v4.0 to at least v4.4"
		hash = "9ecf56e9099811c461d592c325c65c4f9f27d947cbdf3b8ef8a98a43e583aecb"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$deleteFileCOM = {
			48 8B [5]
			45 33 ??
			48 8B ??
			FF 90 90 00 00 00
			85 C0
			75 ??
			48 8B [5]
			48 8B ??
			FF 92 A8 00 00 00
			85 C0
		}
		$copyFileCOM = {
			48 8B [5]
			4C 8B [5]
			48 8B [5]
			48 8B ??
			4C 8B ??
			48 89 [3]
			FF 90 80 00 00 00
			85 C0
			0F 85 [4]
			48 8B [5]
			48 8B 11
			FF 92 A8 00 00 00
		}

	condition:
		all of them
}
