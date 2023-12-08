rule dll_Reg
{
	meta:
		description = "Chinese Hacktool Set - file Reg.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cb8a92fe256a3e5b869f9564ecd1aa9c5c886e3f"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "copy PacketX.dll C:\\windows\\system32\\PacketX.dll" fullword ascii
		$s1 = "regsvr32.exe C:\\windows\\system32\\PacketX.dll" fullword ascii

	condition:
		filesize <1KB and all of them
}
