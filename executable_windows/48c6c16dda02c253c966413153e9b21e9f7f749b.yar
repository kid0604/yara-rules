rule CobaltStrike_Resources_Beacon_x64_v3_14
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.x64.dll Versions 3.14"
		hash = "297a8658aaa4a76599a7b79cb0da5b8aa573dd26c9e2c8f071e591200cf30c93"
		rs2 = "39b9040e3dcd1421a36e02df78fe031cbdd2fb1a9083260b8aedea7c2bc406bf"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 8B D0 49 8B CA 48 83 C4 28 E9 B1 1F 00 00 8B D0 49 8B CA
                     48 83 C4 28 }
		$decoder = { 80 34 28 ?? 48 FF C0 48 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
