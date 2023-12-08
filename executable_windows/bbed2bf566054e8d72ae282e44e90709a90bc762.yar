rule IsDebug_V1_4
{
	meta:
		description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ca32474c358b4402421ece1cb31714fbb088b69a"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "IsDebug.dll" fullword ascii
		$s1 = "SV Dumper V1.0" fullword wide
		$s2 = "(IsDebuggerPresent byte Patcher)" fullword ascii
		$s8 = "Error WriteMemory failed" fullword ascii
		$s9 = "IsDebugPresent" fullword ascii
		$s10 = "idb_Autoload" fullword ascii
		$s11 = "Bin Files" fullword ascii
		$s12 = "MASM32 version" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and all of them
}
