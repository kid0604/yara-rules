import "pe"

rule INDICATOR_KB_CERT_3f8d23c136ae9cbeeac7605b24ec0391
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ff481ea6a887f3b5b941ff7d99a6cdf90c814c40"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bandicam Company" and pe.signatures[i].serial=="3f:8d:23:c1:36:ae:9c:be:ea:c7:60:5b:24:ec:03:91")
}
