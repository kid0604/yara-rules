import "pe"

rule APT1_WARP
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Yara rule for detecting APT1 WARP threat"
		os = "windows"
		filetype = "executable"

	strings:
		$err1 = "exception..." wide ascii
		$err2 = "failed..." wide ascii
		$err3 = "opened..." wide ascii
		$exe1 = "cmd.exe" wide ascii
		$exe2 = "ISUN32.EXE" wide ascii

	condition:
		2 of ($err*) and all of ($exe*)
}
