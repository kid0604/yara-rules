import "pe"

rule MAL_Emotet_BKA_Cleanup_Apr21
{
	meta:
		author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
		reference = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
		descripton = "This rule targets a modified emotet binary deployed by the Bundeskriminalamt on the 26th of January 2021."
		note = "The binary will replace the original emotet by copying it to a quarantine. It also contains a routine to perform a self-deinstallation on the 25th of April 2021. The three-month timeframe between rollout and self-deinstallation was chosen primarily for evidence purposes as well as to allow remediation."
		sharing = "TLP:WHITE"
		date = "2021-03-23"
		description = "Targets a modified emotet binary deployed by the Bundeskriminalamt on the 26th of January 2021."
		os = "windows"
		filetype = "executable"

	strings:
		$key = { c3 da da 19 63 45 2c 86 77 3b e9 fd 24 64 fb b8 07 fe 12 d0 2a 48 13 38 48 68 e8 ae 91 3c ed 82 }

	condition:
		filesize >300KB and filesize <700KB and uint16(0)==0x5A4D and $key
}
