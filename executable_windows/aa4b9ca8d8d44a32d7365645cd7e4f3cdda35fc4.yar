rule Cobaltbaltstrike_RAW_Payload_dns_stager_x86_UTF16
{
	meta:
		author = "Avast Threat Intel Team"
		description = "Detects CobaltStrike payloads"
		reference = "https://github.com/avast/ioc"
		os = "windows"
		filetype = "executable"

	strings:
		$h01 = { FC 00 E8 00 89 00 00 00 00 00 00 00 60 00 89 00 E5 00 31 00 D2 00 64 00 8B 00 52 00 30 00 8B 00 52 00 0C 00 8B 00 52 00 14 00 8B 00 72 00 28 }

	condition:
		uint32(@h01+0x0149)==0xe5005300 and uint32(@h01+0x017d)==0x07002600 and uint32(@h01+0x0261)==0xc9009c00 and uint32(@h01+0x0333)==0x5600a200 and uint32(@h01+0x034b)==0xe0003500 and uint32(@h01+0x03cb)==0xcc008e00
}
