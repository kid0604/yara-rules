rule CobaltStrike_Sleeve_Beacon_Dll_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/beacon.dll Versions 4.3 and 4.4"
		hash = "51490c01c72c821f476727c26fbbc85bdbc41464f95b28cdc577e5701790845f"
		rs2 = "78a6fbefa677eeee29d1af4a294ee57319221b329a2fe254442f5708858b37dc"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$version_sig = { 48 57 8B F2 83 F8 65 0F 87 47 03 00 00 FF 24 }
		$decoder = { 80 B0 [4] ?? 40 3D 00 10 00 00 7C F1 }

	condition:
		all of them
}
