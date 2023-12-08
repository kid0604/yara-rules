rule HKTL_NET_GUID_ManagedInjection
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/malcomvetter/ManagedInjection"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "e5182bff-9562-40ff-b864-5a6b30c3b13b" ascii nocase wide
		$typelibguid1 = "fdedde0d-e095-41c9-93fb-c2219ada55b1" ascii nocase wide
		$typelibguid2 = "0dd00561-affc-4066-8c48-ce950788c3c8" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
