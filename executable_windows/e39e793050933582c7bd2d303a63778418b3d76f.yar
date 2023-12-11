rule HKTL_NET_GUID_PortTran
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/k8gege/PortTran"
		author = "Arnim Rupp"
		date = "2020-12-29"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "3a074374-77e8-4312-8746-37f3cb00e82c" ascii nocase wide
		$typelibguid1 = "67a73bac-f59d-4227-9220-e20a2ef42782" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
