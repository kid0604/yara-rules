import "pe"

rule APT1_GETMAIL
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects APT1 threat group attempting to retrieve email data"
		os = "windows"
		filetype = "executable"

	strings:
		$stra1 = "pls give the FULL path" wide ascii
		$stra2 = "mapi32.dll" wide ascii
		$stra3 = "doCompress" wide ascii
		$strb1 = "getmail.dll" wide ascii
		$strb2 = "doCompress" wide ascii
		$strb3 = "love" wide ascii

	condition:
		all of ($stra*) or all of ($strb*)
}
