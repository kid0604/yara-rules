import "pe"

rule HKTL_NET_GUID_MemeVM_alt_1
{
	meta:
		description = "Detects .NET red/black-team tools via typelibguid"
		reference = "https://github.com/TobitoFatitoRE/MemeVM"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021-01-21"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "ef18f7f2-1f03-481c-98f9-4a18a2f12c11" ascii wide
		$typelibguid0up = "EF18F7F2-1F03-481C-98F9-4A18A2F12C11" ascii wide
		$typelibguid1lo = "77b2c83b-ca34-4738-9384-c52f0121647c" ascii wide
		$typelibguid1up = "77B2C83B-CA34-4738-9384-C52F0121647C" ascii wide
		$typelibguid2lo = "14d5d12e-9a32-4516-904e-df3393626317" ascii wide
		$typelibguid2up = "14D5D12E-9A32-4516-904E-DF3393626317" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
