import "pe"

rule HKTL_NET_GUID_The_Collection_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/Tlgyt/The-Collection"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "579159ff-3a3d-46a7-b069-91204feb21cd" ascii wide
		$typelibguid0up = "579159FF-3A3D-46A7-B069-91204FEB21CD" ascii wide
		$typelibguid1lo = "5b7dd9be-c8c3-4c4f-a353-fefb89baa7b3" ascii wide
		$typelibguid1up = "5B7DD9BE-C8C3-4C4F-A353-FEFB89BAA7B3" ascii wide
		$typelibguid2lo = "43edcb1f-3098-4a23-a7f2-895d927bc661" ascii wide
		$typelibguid2up = "43EDCB1F-3098-4A23-A7F2-895D927BC661" ascii wide
		$typelibguid3lo = "5f19919d-cd51-4e77-973f-875678360a6f" ascii wide
		$typelibguid3up = "5F19919D-CD51-4E77-973F-875678360A6F" ascii wide
		$typelibguid4lo = "17fbc926-e17e-4034-ba1b-fb2eb57f5dd3" ascii wide
		$typelibguid4up = "17FBC926-E17E-4034-BA1B-FB2EB57F5DD3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
