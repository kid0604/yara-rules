rule HKTL_NET_GUID_TheHackToolBoxTeek
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/teeknofil/TheHackToolBoxTeek"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "2aa8c254-b3b3-469c-b0c9-dcbe1dd101c0" ascii nocase wide
		$typelibguid1 = "afeff505-14c1-4ecf-b714-abac4fbd48e7" ascii nocase wide
		$typelibguid2 = "4cf42167-a5cf-4b2d-85b4-8e764c08d6b3" ascii nocase wide
		$typelibguid3 = "118a90b7-598a-4cfc-859e-8013c8b9339c" ascii nocase wide
		$typelibguid4 = "3075dd9a-4283-4d38-a25e-9f9845e5adcb" ascii nocase wide
		$typelibguid5 = "295655e8-2348-4700-9ebc-aa57df54887e" ascii nocase wide
		$typelibguid6 = "74efe601-9a93-46c3-932e-b80ab6570e42" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
