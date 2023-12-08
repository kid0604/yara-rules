import "pe"

rule INDICATOR_KB_CERT_66f98881fbb02d0352bef7c13bd61df2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "722eee34153fc67ea7abdcb0c6e9e54479f1580e"
		hash = "f265524fb9a4a58274dbd32b2ed0c3f816c5eff05e1007a2e7bba286b8ffa72c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="66:f9:88:81:fb:b0:2d:03:52:be:f7:c1:3b:d6:1d:f2")
}
