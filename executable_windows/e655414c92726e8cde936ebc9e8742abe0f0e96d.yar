import "pe"

rule APT1_WEBC2_TOCK
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects APT1 threat group activity related to the Tock malware communicating with a web C2 server"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "InprocServer32" wide ascii
		$2 = "HKEY_PERFORMANCE_DATA" wide ascii
		$3 = "<!---[<if IE 5>]id=" wide ascii

	condition:
		all of them
}
