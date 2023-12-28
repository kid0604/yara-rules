rule BlackTech_SpiderRAT_str
{
	meta:
		description = "Spider(SpiderPig) RAT in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash = "C2B23689CA1C57F7B7B0C2FD95BFEF326D6A22C15089D35D31119B104978038B"
		os = "windows"
		filetype = "executable"

	strings:
		$msg1 = "InternetSetOption m_ProxyUserName Error."
		$msg2 = "InternetSetOption m_ProxyPassWord Error."
		$msg3 = "pWork->HC->HttpSendMessage failed!"
		$msg4 = "Recv_put error!"
		$msg5 = "Send_put error!"
		$msg6 = "Send Success - %d:%d"
		$msg7 = "Recv Success - %d:%d"

	condition:
		uint16(0)==0x5A4D and 5 of ($msg*)
}
