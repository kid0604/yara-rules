import "pe"

rule HKTL_NET_GUID_Inception_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/two06/Inception"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "03d96b8c-efd1-44a9-8db2-0b74db5d247a" ascii wide
		$typelibguid0up = "03D96B8C-EFD1-44A9-8DB2-0B74DB5D247A" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
