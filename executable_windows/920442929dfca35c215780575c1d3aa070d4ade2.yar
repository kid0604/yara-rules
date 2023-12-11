import "pe"

rule HKTL_NET_GUID_CVE_2020_1206_POC_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/ZecOps/CVE-2020-1206-POC"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "3523ca04-a12d-4b40-8837-1a1d28ef96de" ascii wide
		$typelibguid0up = "3523CA04-A12D-4B40-8837-1A1D28EF96DE" ascii wide
		$typelibguid1lo = "d3a2f24a-ddc6-4548-9b3d-470e70dbcaab" ascii wide
		$typelibguid1up = "D3A2F24A-DDC6-4548-9B3D-470E70DBCAAB" ascii wide
		$typelibguid2lo = "fb30ee05-4a35-45f7-9a0a-829aec7e47d9" ascii wide
		$typelibguid2up = "FB30EE05-4A35-45F7-9A0A-829AEC7E47D9" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
