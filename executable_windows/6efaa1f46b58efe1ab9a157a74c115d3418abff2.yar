import "pe"

rule INDICATOR_KB_CERT_008cff807edaf368a60e4106906d8df319
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c97d809c73f376cdf8062329b357b16c9da9d14261895cd52400f845a2d6bdb1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KRAFT BOKS OOO" and pe.signatures[i].serial=="00:8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19")
}
