import "pe"

rule INDICATOR_KB_CERT_a0a27aefd067ac62ce0247b72bf33de3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "42c2842fa674fdca14c9786aaec0c3078a4f1755"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cfbcdabfdbdccaaccadfeaacacf" and pe.signatures[i].serial=="a0:a2:7a:ef:d0:67:ac:62:ce:02:47:b7:2b:f3:3d:e3")
}
