import "pe"

rule INDICATOR_KB_CERT_1f55ae3fca38827cde6cc7ca1c0d2731
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a279fa4186ef598c5498ba5c0037c7bd4bd57272"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fcceaeafbbdccccddfbbb" and pe.signatures[i].serial=="1f:55:ae:3f:ca:38:82:7c:de:6c:c7:ca:1c:0d:27:31")
}
