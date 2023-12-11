rule HKTL_NET_GUID_Misc_CSharp
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/Misc-CSharp"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "d1421ba3-c60b-42a0-98f9-92ba4e653f3d" ascii nocase wide
		$typelibguid1 = "2afac0dd-f46f-4f95-8a93-dc17b4f9a3a1" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
