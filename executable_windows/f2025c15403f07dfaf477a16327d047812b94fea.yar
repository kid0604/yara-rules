import "pe"

rule INDICATOR_KB_CERT_009cfbb4c69008821aaacecde97ee149ab
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6c7e917a2cc2b2228d6d4a0556bda6b2db9f06691749d2715af9a6a283ec987b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kivaliz Prest s.r.l." and pe.signatures[i].serial=="00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab")
}
