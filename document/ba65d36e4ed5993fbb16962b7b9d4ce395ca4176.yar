rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_2
{
	meta:
		description = "Detects suspicious OneNote attachment that has a file name often used in phishing attacks"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2023-01-27"
		score = 65
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$hc1 = { 2E 6F 6E 65 22 0D 0A 0D 0A 35 46 4A 63 65 }
		$x01 = " attachment; filename=\"Invoice" nocase
		$x02 = " attachment; filename=\"ORDER" nocase
		$x03 = " attachment; filename=\"PURCHASE" nocase
		$x04 = " attachment; filename=\"SHIP" nocase

	condition:
		filesize <5MB and $hc1 and 1 of ($x*)
}
