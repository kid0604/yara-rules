import "pe"

rule INDICATOR_KB_CERT_45245eef53fcf38169c715cf68f44452
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ad7edb1b0a6a1ee3297a8825aff090030142dce8b59b9261bc57ca86666b0cbe"
		reason = "QuakBot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PAPER AND CORE SUPPLIES LTD" and pe.signatures[i].serial=="45:24:5e:ef:53:fc:f3:81:69:c7:15:cf:68:f4:44:52")
}
