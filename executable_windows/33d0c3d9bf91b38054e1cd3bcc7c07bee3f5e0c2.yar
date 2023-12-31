import "pe"

rule APT1_WEBC2_HEAD
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects APT1 Web C2 communication"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "Ready!" wide ascii
		$2 = "connect ok" wide ascii
		$3 = "WinHTTP 1.0" wide ascii
		$4 = "<head>" wide ascii

	condition:
		all of them
}
