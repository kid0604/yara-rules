import "pe"

rule DLL_Injector_Lynx
{
	meta:
		description = "Detects Lynx DLL Injector"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-08-20"
		hash1 = "d594f60e766e0c3261a599b385e3f686b159a992d19fa624fad8761776efa4f0"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = " -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> [--obfuscate]" fullword wide
		$x2 = "You've selected to inject into process: %s" fullword wide
		$x3 = "Lynx DLL Injector" fullword wide
		$x4 = "Reflective DLL Injector" fullword wide
		$x5 = "Failed write payload: %lu" fullword wide
		$x6 = "Failed to start payload: %lu" fullword wide
		$x7 = "Injecting payload..." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and 1 of them ) or (3 of them )
}
