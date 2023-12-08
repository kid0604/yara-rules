import "pe"

rule INDICATOR_KB_CERT_0af9b523180f34a24fcfd11b74e7d6cd
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c8aec622951068734d754dc2efd7032f9ac572e26081ac38b8ceb333ccc165c9"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORBIS LTD" and pe.signatures[i].serial=="0a:f9:b5:23:18:0f:34:a2:4f:cf:d1:1b:74:e7:d6:cd")
}
