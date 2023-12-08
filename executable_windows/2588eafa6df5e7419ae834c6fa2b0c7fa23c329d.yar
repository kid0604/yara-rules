rule CobaltStrike_Sleeve_Beacon_Dll_x86_v4_0_suspected
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 4.0 (suspected, not confirmed)"
		hash = "55aa2b534fcedc92bb3da54827d0daaa23ece0f02a10eb08f5b5247caaa63a73"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 41 B8 01 00 00 00 8B D0 49 8B CA 48 83 C4 28 E9 D1 B3 FF FF
                     8B D0 49 8B CA 48 83 C4 28 E9 AF F5 FF FF 45 33 C0
                     4C 8D 0D 8D 70 FF FF 8B D0 49 8B CA E8 9B B0 FF FF }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
