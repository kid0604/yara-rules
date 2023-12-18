import "pe"

rule INDICATOR_KB_CERT_a32f3ba229704ad400473f7479e4c3e4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ab4b30913895d8df383fdadebc29d2e04a5c854bc4172c0d41bcbef176e8f37e"
		reason = "RecordBreaker"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SOTUL SOLUTIONS LIMITED" and pe.signatures[i].serial=="a3:2f:3b:a2:29:70:4a:d4:00:47:3f:74:79:e4:c3:e4")
}
