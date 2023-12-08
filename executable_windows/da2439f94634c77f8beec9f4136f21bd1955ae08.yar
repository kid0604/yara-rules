import "pe"

rule INDICATOR_KB_CERT_25ad5ae68c38ad1021086f4ffc8ba470
{
	meta:
		author = "ditekSHen"
		description = "Enigma Protector CA Certificate"
		thumbprint = "a04c0281bc2203a95ef9bd6d9736486449d80905"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Enigma Protector CA" and pe.signatures[i].serial=="25:ad:5a:e6:8c:38:ad:10:21:08:6f:4f:fc:8b:a4:70")
}
