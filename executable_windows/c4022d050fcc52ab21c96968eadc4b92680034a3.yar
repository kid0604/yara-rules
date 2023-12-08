import "pe"

rule INDICATOR_KB_CERT_0092d9b92f8cf7a1ba8b2c025be730c300
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b891c96bd8548c60fa86b753f0c4a4ccc7ab51256b4ee984b5187c62470f9396"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "UPLagga Systems s.r.o." and pe.signatures[i].serial=="00:92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00")
}
