import "pe"

rule INDICATOR_KB_CERT_028d50ae0c554b49148e82db5b1c2699
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "0abdbc13639c704ff325035439ea9d20b08bc48e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VAS CO PTY LTD" and pe.signatures[i].serial=="02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99")
}
