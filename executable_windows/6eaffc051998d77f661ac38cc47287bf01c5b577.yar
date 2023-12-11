import "pe"

rule AURIGA_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting AURIGA APT1 threat"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "superhard corp." wide ascii
		$s2 = "microsoft corp." wide ascii
		$s3 = "[Insert]" wide ascii
		$s4 = "[Delete]" wide ascii
		$s5 = "[End]" wide ascii
		$s6 = "!(*@)(!@KEY" wide ascii
		$s7 = "!(*@)(!@SID=" wide ascii

	condition:
		all of them
}
