import "pe"

rule INDICATOR_KB_CERT_a2253aeb5b0ff1aecbfd412c18ccf07a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b03db8e908dcf0e00a5a011ba82e673d91524816"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gallopers Software Solutions Limited" and pe.signatures[i].serial=="a2:25:3a:eb:5b:0f:f1:ae:cb:fd:41:2c:18:cc:f0:7a")
}
