rule SUSP_PE_Discord_Attachment_Oct21_1
{
	meta:
		description = "Detects suspicious executable with reference to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2021-10-12"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "https://cdn.discordapp.com/attachments/" ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and 1 of them
}
