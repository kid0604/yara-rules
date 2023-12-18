import "pe"

rule INDICATOR_KB_CERT_5294f0f841f29855e33a18402421949a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "df744f6b9430237821e3f2bc6edafb4a92354dda1734a60d5e0d816256aefb47"
		reason = "RemcosRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Integrated Plotting Solutions Limited" and pe.signatures[i].serial=="52:94:f0:f8:41:f2:98:55:e3:3a:18:40:24:21:94:9a")
}
