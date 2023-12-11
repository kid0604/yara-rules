rule HKTL_NET_GUID_The_Collection
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Tlgyt/The-Collection"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "579159ff-3a3d-46a7-b069-91204feb21cd" ascii nocase wide
		$typelibguid1 = "5b7dd9be-c8c3-4c4f-a353-fefb89baa7b3" ascii nocase wide
		$typelibguid2 = "43edcb1f-3098-4a23-a7f2-895d927bc661" ascii nocase wide
		$typelibguid3 = "5f19919d-cd51-4e77-973f-875678360a6f" ascii nocase wide
		$typelibguid4 = "17fbc926-e17e-4034-ba1b-fb2eb57f5dd3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
