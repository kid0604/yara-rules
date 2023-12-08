import "pe"

rule INDICATOR_KB_CERT_003223b4616c2687c04865bee8321726a8
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "321218e292c2c489bbc7171526e1b4e02ef68ce23105eee87832f875b871ed9f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and pe.signatures[i].serial=="32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8")
}
