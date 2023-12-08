import "pe"

rule HKTL_NET_GUID_KeystrokeAPI_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/fabriciorissetto/KeystrokeAPI"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "f6fec17e-e22d-4149-a8a8-9f64c3c905d3" ascii wide
		$typelibguid0up = "F6FEC17E-E22D-4149-A8A8-9F64C3C905D3" ascii wide
		$typelibguid1lo = "b7aa4e23-39a4-49d5-859a-083c789bfea2" ascii wide
		$typelibguid1up = "B7AA4E23-39A4-49D5-859A-083C789BFEA2" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
