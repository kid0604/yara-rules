rule HKTL_NET_GUID_ExploitRemotingService
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/tyranid/ExploitRemotingService"
		author = "Arnim Rupp"
		date = "2020-12-21"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "fd17ae38-2fd3-405f-b85b-e9d14e8e8261" ascii nocase wide
		$typelibguid1 = "1850b9bb-4a23-4d74-96b8-58f274674566" ascii nocase wide
		$typelibguid2 = "297cbca1-efa3-4f2a-8d5f-e1faf02ba587" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
