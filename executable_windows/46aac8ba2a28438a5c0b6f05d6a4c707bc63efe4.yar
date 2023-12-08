rule Cobaltbaltstrike_RAW_Payload_http_stager_x86_UTF16
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
		uint32(@h01+0x013b)==0x07002600 and uint32(@h01+0x0157)==0xa7007900 and uint32(@h01+0x018f)==0xc6009f00 and uint32(@h01+0x01bf)==0x3b002e00 and uint32(@h01+0x01e7)==0x7b001800 and uint32(@h01+0x0219)==0x5d00e200 and uint32(@h01+0x022b)==0x31005e00 and uint32(@h01+0x0249)==0x0b00e000 and uint32(@h01+0x058b)==0x5600a200 and uint32(@h01+0x05b3)==0xe5005300 and uint32(@h01+0x05e9)==0xe2008900
}
