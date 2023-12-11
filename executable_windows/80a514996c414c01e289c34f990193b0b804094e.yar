rule HKTL_NET_GUID_SharpSpray
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpSpray"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "51c6e016-1428-441d-82e9-bb0eb599bbc8" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
