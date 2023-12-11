import "pe"

rule INDICATOR_KB_CERT_510c5e540503f30c9caa3082296aa452
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3e56a13ceb87243b8b2c5de67da54a3a9e0988d7"
		hash = "cb01f31a322572035cf19f6cda00bcf1d8235dcc692588810405d0fc6e8d239c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Systems Analysis 360 Ltd" and pe.signatures[i].serial=="51:0c:5e:54:05:03:f3:0c:9c:aa:30:82:29:6a:a4:52")
}
