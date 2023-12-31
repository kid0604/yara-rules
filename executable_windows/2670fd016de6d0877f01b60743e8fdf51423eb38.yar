import "pe"

rule APT1_TARSIP_ECLIPSE
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting APT1 TARSIP ECLIPSE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "\\pipe\\ssnp" wide ascii
		$2 = "toobu.ini" wide ascii
		$3 = "Serverfile is not bigger than Clientfile" wide ascii
		$4 = "URL download success" wide ascii

	condition:
		3 of them
}
