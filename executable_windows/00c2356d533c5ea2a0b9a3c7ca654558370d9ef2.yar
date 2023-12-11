rule APT_Malware_PutterPanda_WUAUCLT
{
	meta:
		description = "Detects a malware related to Putter Panda"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "fd5ca5a2d444865fa8320337467313e4026b9f78"
		os = "windows"
		filetype = "executable"

	strings:
		$x0 = "WUAUCLT.EXE" fullword wide
		$x1 = "%s\\tmp%d.exe" fullword ascii
		$x2 = "Microsoft Corporation. All rights reserved." fullword wide
		$s1 = "Microsoft Windows Operating System" fullword wide
		$s2 = "InternetQueryOptionA" fullword ascii
		$s3 = "LookupPrivilegeValueA" fullword ascii
		$s4 = "WNetEnumResourceA" fullword ascii
		$s5 = "HttpSendRequestExA" fullword ascii
		$s6 = "PSAPI.DLL" fullword ascii
		$s7 = "Microsoft(R) Windows(R) Operating System" fullword wide
		$s8 = "CreatePipe" fullword ascii
		$s9 = "EnumProcessModules" fullword ascii

	condition:
		all of ($x*) or (1 of ($x*) and all of ($s*))
}
