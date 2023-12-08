rule EXPL_SUSP_Outlook_CVE_2023_23397_SMTP_Mail_Mar23
{
	meta:
		author = "Nils Kuhnert"
		date = "2023-03-17"
		modified = "2023-03-24"
		description = "Detects suspicious *.eml files that include TNEF content that possibly exploits CVE-2023-23397. Lower score than EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 as we're only looking for UNC prefix."
		score = 60
		reference = "https://twitter.com/wdormann/status/1636491612686622723"
		os = "windows"
		filetype = "document"

	strings:
		$mail1 = { 0A 46 72 6F 6D 3A 20 }
		$mail2 = { 0A 54 6F 3A }
		$mail3 = { 0A 52 65 63 65 69 76 65 64 3A }
		$tnef1 = "Content-Type: application/ms-tnef" ascii
		$tnef2 = "\x78\x9f\x3e\x22" base64
		$ipm1 = "IPM.Task" base64
		$ipm2 = "IPM.Appointment" base64
		$unc = "\x00\x00\x00\x5c\x5c" base64

	condition:
		all of ($mail*) and all of ($tnef*) and 1 of ($ipm*) and $unc
}
