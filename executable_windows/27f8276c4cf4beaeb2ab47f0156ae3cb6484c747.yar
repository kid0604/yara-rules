import "pe"

rule INDICATOR_KB_CERT_00ced72cc75aa0ebce09dc0283076ce9b1
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "db77b48a7f16fecd49029b65f122fa0782b4318f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Valerie LLC" and pe.signatures[i].serial=="00:ce:d7:2c:c7:5a:a0:eb:ce:09:dc:02:83:07:6c:e9:b1")
}
