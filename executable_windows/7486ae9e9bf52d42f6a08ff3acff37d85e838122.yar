import "pe"

rule ccrewSSLBack2
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects the presence of CommentCrew threat APT1 using SSL backdoor"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {39 82 49 42 BE 1F 3A}

	condition:
		any of them
}
