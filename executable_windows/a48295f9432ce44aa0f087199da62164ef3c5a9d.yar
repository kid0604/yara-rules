rule HKTL_NET_GUID_RAT_TelegramSpyBot
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/SebastianEPH/RAT.TelegramSpyBot"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8653fa88-9655-440e-b534-26c3c760a0d3" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
