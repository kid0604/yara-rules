import "pe"

rule INDICATOR_KB_CERT_00849ea0945dd2ea2dc3cc2486578a5715
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8c56adfb8fba825aa9a4ab450c71d45b950e55a4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Biglin" and pe.signatures[i].serial=="00:84:9e:a0:94:5d:d2:ea:2d:c3:cc:24:86:57:8a:57:15")
}
