import "pe"

rule GLOOXMAIL_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting GLOOXMAIL APT1 threat"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Kill process success!" wide ascii
		$s2 = "Kill process failed!" wide ascii
		$s3 = "Sleep success!" wide ascii
		$s4 = "based on gloox" wide ascii
		$pdb = "glooxtest.pdb" wide ascii

	condition:
		all of ($s*) or $pdb
}
