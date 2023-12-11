import "pe"

rule APT1_WEBC2_TABLE
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects APT1 threat activity related to web C2 communication"
		os = "windows"
		filetype = "executable"

	strings:
		$msg1 = "Fail To Execute The Command" wide ascii
		$msg2 = "Execute The Command Successfully" wide ascii
		$gif2 = "GIF89" wide ascii

	condition:
		3 of them
}
