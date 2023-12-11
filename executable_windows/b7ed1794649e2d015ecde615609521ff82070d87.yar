import "pe"

rule ccrewSSLBack3
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects the presence of the CommentCrew threat (APT1) related to SSL backdoor"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "SLYHKAAY" wide ascii

	condition:
		any of them
}
