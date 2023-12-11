rule CobaltStrike_Sleeve_BeaconLoader_HA_x86_o_v4_3_v4_4_v4_5_and_v4_6
{
	meta:
		description = "Cobalt Strike's sleeve/BeaconLoader.HA.x86.o (HeapAlloc) Versions 4.3 through at least 4.6"
		hash = "8e4a1862aa3693f0e9011ade23ad3ba036c76ae8ccfb6585dc19ceb101507dcd"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "executable"

	strings:
		$core_sig = {
      C6 45 F0 48
      C6 45 F1 65
      C6 45 F2 61
      C6 45 F3 70
      C6 45 F4 41
      C6 45 F5 6C
      C6 45 F6 6C
      C6 45 F7 6F
      C6 45 F8 63
      C6 45 F9 00
    }

	condition:
		all of them
}
