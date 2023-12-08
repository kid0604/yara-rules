rule HKTL_NET_GUID_VanillaRAT
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/DannyTheSloth/VanillaRAT"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "d0f2ee67-0a50-423d-bfe6-845da892a2db" ascii nocase wide
		$typelibguid1 = "a593fcd2-c8ab-45f6-9aeb-8ab5e20ab402" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
