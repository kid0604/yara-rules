import "pe"

rule HKTL_NET_GUID_OffensivePowerShellTasking_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/leechristensen/OffensivePowerShellTasking"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "d432c332-3b48-4d06-bedb-462e264e6688" ascii wide
		$typelibguid0up = "D432C332-3B48-4D06-BEDB-462E264E6688" ascii wide
		$typelibguid1lo = "5796276f-1c7a-4d7b-a089-550a8c19d0e8" ascii wide
		$typelibguid1up = "5796276F-1C7A-4D7B-A089-550A8C19D0E8" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
