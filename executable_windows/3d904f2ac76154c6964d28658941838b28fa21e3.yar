import "pe"

rule APT1_WEBC2_BOLID
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects APT1 threat group using VMProtect and specific C2 communication"
		os = "windows"
		filetype = "executable"

	strings:
		$vm = "VMProtect" wide ascii
		$http = "http://[c2_location]/[page].html" wide ascii

	condition:
		all of them
}
