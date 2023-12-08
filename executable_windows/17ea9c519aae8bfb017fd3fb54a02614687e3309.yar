import "pe"

rule HKTL_NET_GUID_RegistryStrikesBack_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/mdsecactivebreach/RegistryStrikesBack"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "90ebd469-d780-4431-9bd8-014b00057665" ascii wide
		$typelibguid0up = "90EBD469-D780-4431-9BD8-014B00057665" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
