rule Cobaltbaltstrike_Beacon_XORed_x64
{
	meta:
		author = "Avast Threat Intel Team"
		description = "Detects CobaltStrike payloads"
		reference = "https://github.com/avast/ioc"
		os = "windows"
		filetype = "executable"

	strings:
		$h01 = { FC 4883E4F0 EB33 5D 8B4500 4883C504 8B4D00 31C1 4883C504 55 8B5500 31C2 895500 31D0 4883C504 83E904 31D2 39D1 7402 EBE7 58 FC 4883E4F0 FFD0 E8C8FFFFFF }
		$h11 = { FC 4883E4F0 FFD0 E8C8FFFFFF }

	condition:
		$h01 and ( uint32be(@h11+12)^ uint32be(@h11+20)==0x4D5A4152 or uint32be(@h11+12)^ uint32be(@h11+20)==0x904D5A41 or uint32be(@h11+12)^ uint32be(@h11+20)==0x90904D5A or uint32be(@h11+12)^ uint32be(@h11+20)==0x9090904D or uint32be(@h11+12)^ uint32be(@h11+20)==0x90909090)
}
