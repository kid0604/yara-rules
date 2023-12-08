rule HKTL_NET_GUID_SharpAttack
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/jaredhaight/SharpAttack"
		author = "Arnim Rupp"
		date = "2020-12-28"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "5f0ceca3-5997-406c-adf5-6c7fbb6cba17" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
