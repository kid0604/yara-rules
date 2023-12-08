rule HKTL_NET_GUID_KeystrokeAPI
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fabriciorissetto/KeystrokeAPI"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "f6fec17e-e22d-4149-a8a8-9f64c3c905d3" ascii nocase wide
		$typelibguid1 = "b7aa4e23-39a4-49d5-859a-083c789bfea2" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
