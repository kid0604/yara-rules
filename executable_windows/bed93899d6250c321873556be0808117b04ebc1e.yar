import "pe"

rule INDICATOR_KB_CERT_0085e1af2be0f380e5a5d11513ddf45fc6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e9849101535b47ff2a67e4897113c06f024d33f575baa5b426352f15116b98b4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Makke Digital Works" and pe.signatures[i].serial=="00:85:e1:af:2b:e0:f3:80:e5:a5:d1:15:13:dd:f4:5f:c6")
}
