rule CobaltStrike_Resources_Beacon_Dll_v1_45
{
	meta:
		description = "Cobalt Strike's resources/beacon.dll Version 1.45"
		hash = "1a92b2024320f581232f2ba1e9a11bef082d5e9723429b3e4febb149458d1bb1"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 51 0F B7 D2 4A 53 56 83 FA 08 77 6B FF 24 }
		$decode = { B1 ?? 30 88 [4] 40 3D 28 01 00 00 7C F2 }

	condition:
		all of them
}
