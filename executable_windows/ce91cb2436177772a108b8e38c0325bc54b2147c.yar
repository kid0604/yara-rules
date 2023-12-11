import "pe"

rule HKTL_NET_GUID_SharpReg_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/jnqpblc/SharpReg"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "8ef25b00-ed6a-4464-bdec-17281a4aa52f" ascii wide
		$typelibguid0up = "8EF25B00-ED6A-4464-BDEC-17281A4AA52F" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
