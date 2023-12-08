import "pe"

rule APT1_RARSilent_EXE_PDF
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects APT1 RAR Silent EXE PDF"
		os = "windows"
		filetype = "executable"

	strings:
		$winrar1 = "WINRAR.SFX" wide ascii
		$str2 = "Steup=" wide ascii

	condition:
		all of them
}
