rule HKTL_NET_GUID_SharpGPO_RemoteAccessPolicies
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FSecureLABS/SharpGPO-RemoteAccessPolicies"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "script"

	strings:
		$typelibguid0 = "fbb1abcf-2b06-47a0-9311-17ba3d0f2a50" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
