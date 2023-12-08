import "pe"

rule HKTL_NET_GUID_Lime_Miner_alt_1
{
	meta:
		description = "Detects VB.NET red/black-team tools via typelibguid"
		reference = "https://github.com/NYAN-x-CAT/Lime-Miner"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-30"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "13958fb9-dfc1-4e2c-8a8d-a5e68abdbc66" ascii wide
		$typelibguid0up = "13958FB9-DFC1-4E2C-8A8D-A5E68ABDBC66" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
