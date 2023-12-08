import "pe"

rule HKTL_NET_GUID_NashaVM_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/Mrakovic-ORG/NashaVM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "f9e63498-6e92-4afd-8c13-4f63a3d964c3" ascii wide
		$typelibguid0up = "F9E63498-6E92-4AFD-8C13-4F63A3D964C3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
