import "pe"

rule APT1_WEBC2_UGX
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects APT1 Web C2 persistence mechanism"
		os = "windows"
		filetype = "executable"

	strings:
		$persis = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" wide ascii
		$exe = "DefWatch.exe" wide ascii
		$html = "index1.html" wide ascii
		$cmd1 = "!@#tiuq#@!" wide ascii
		$cmd2 = "!@#dmc#@!" wide ascii
		$cmd3 = "!@#troppusnu#@!" wide ascii

	condition:
		3 of them
}
