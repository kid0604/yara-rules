import "pe"

rule ccrewQAZ
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects the presence of the CommentCrew threat APT1"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "!QAZ@WSX" wide ascii

	condition:
		$a
}
