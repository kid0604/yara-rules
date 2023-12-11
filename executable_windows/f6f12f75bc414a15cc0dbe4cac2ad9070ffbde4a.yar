import "pe"

rule HKTL_NET_GUID_UnstoppableService_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malcomvetter/UnstoppableService"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "0c117ee5-2a21-dead-beef-8cc7f0caaa86" ascii wide
		$typelibguid0up = "0C117EE5-2A21-DEAD-BEEF-8CC7F0CAAA86" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
