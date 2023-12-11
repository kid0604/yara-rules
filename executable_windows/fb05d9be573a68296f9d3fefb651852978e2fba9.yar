import "pe"

rule INDICATOR_KB_CERT_566ac16a57b132d3f64dced14de790ee
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2e44464a5907ac46981bebd8eed86d8deec9a4cfafdf1652c8ba68551d4443ff"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Unirad LLC" and pe.signatures[i].serial=="56:6a:c1:6a:57:b1:32:d3:f6:4d:ce:d1:4d:e7:90:ee")
}
