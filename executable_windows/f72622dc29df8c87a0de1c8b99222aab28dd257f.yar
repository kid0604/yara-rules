rule HKTL_NET_GUID_MinerDropper
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/DylanAlloy/MinerDropper"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "46a7af83-1da7-40b2-9d86-6fd6223f6791" ascii nocase wide
		$typelibguid1 = "8433a693-f39d-451b-955b-31c3e7fa6825" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
