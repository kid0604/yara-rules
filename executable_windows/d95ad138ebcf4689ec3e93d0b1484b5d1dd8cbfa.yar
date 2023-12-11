import "pe"

rule HKTL_NET_GUID_C_Sharp_R_A_T_Client_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/AdvancedHacker101/C-Sharp-R.A.T-Client"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-28"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "6d9e8852-e86c-4e36-9cb4-b3c3853ed6b8" ascii wide
		$typelibguid0up = "6D9E8852-E86C-4E36-9CB4-B3C3853ED6B8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
