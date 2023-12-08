import "pe"

rule HKTL_NET_GUID_SharpGPO_RemoteAccessPolicies_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FSecureLABS/SharpGPO-RemoteAccessPolicies"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "fbb1abcf-2b06-47a0-9311-17ba3d0f2a50" ascii wide
		$typelibguid0up = "FBB1ABCF-2B06-47A0-9311-17BA3D0F2A50" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
