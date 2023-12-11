import "pe"

rule HKTL_NET_GUID_RAT_TelegramSpyBot_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SebastianEPH/RAT.TelegramSpyBot"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "8653fa88-9655-440e-b534-26c3c760a0d3" ascii wide
		$typelibguid0up = "8653FA88-9655-440E-B534-26C3C760A0D3" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
