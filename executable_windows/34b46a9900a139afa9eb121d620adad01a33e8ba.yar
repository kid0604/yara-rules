import "pe"

rule Elise_alt_1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting SetElise.pdb related to CommentCrew threat APT1"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "SetElise.pdb" wide ascii

	condition:
		$a
}
