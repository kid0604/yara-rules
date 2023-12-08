import "pe"

rule INDICATOR_KB_CERT_00cfae7e6f538b9f2e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3152fc5298e42de08ed2dec23d8fefcaa531c771"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SequenceDesigner" and (pe.signatures[i].serial=="cf:ae:7e:6f:53:8b:9f:2e" or pe.signatures[i].serial=="00:cf:ae:7e:6f:53:8b:9f:2e"))
}
