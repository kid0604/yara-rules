rule HKTL_NET_GUID_Crypter_Runtime_AV_s_bypass
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/netreverse/Crypter-Runtime-AV-s-bypass"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "c25e39a9-8215-43aa-96a3-da0e9512ec18" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
