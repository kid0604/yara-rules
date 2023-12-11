import "pe"

rule APT1_WEBC2_ADSPACE
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects APT1 Web C2 Adspace"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "<!---HEADER ADSPACE style=" wide ascii
		$2 = "ERSVC.DLL" wide ascii

	condition:
		all of them
}
