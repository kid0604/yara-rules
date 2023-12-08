import "pe"

rule APT_CN_APT27_Compromised_Certficate_Jan22_1
{
	meta:
		description = "Detects compromised certifcates used by APT27 malware"
		author = "Florian Roth (Nextron Systems)"
		date = "2022-01-29"
		score = 80
		reference = "https://www.verfassungsschutz.de/SharedDocs/publikationen/DE/cyberabwehr/2022-01-bfv-cyber-brief.pdf"
		os = "windows"
		filetype = "executable"

	condition:
		for any i in (0..pe.number_of_signatures) : (pe.signatures[i].issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and pe.signatures[i].serial=="08:68:70:51:50:f1:cf:c1:fc:c3:fc:91:a4:49:49:a6")
}
