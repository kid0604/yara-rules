import "pe"

rule INDICATOR_KB_CERT_07cf63bdccc15c55e5ce785bdfbeaacf
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3306df7607bed04187d23c1eb93adf2998e51d01"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "REITSUPER ESTATE LLC" and pe.signatures[i].serial=="07:cf:63:bd:cc:c1:5c:55:e5:ce:78:5b:df:be:aa:cf")
}
