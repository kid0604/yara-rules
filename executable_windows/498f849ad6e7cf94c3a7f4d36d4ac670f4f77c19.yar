import "pe"

rule HKTL_NET_GUID_Simple_Loader_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/cribdragg3r/Simple-Loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "035ae711-c0e9-41da-a9a2-6523865e8694" ascii wide
		$typelibguid0up = "035AE711-C0E9-41DA-A9A2-6523865E8694" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
