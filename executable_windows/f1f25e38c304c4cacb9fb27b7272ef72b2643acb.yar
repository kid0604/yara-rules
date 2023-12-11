import "pe"

rule BOUNCER_DLL_APT1
{
	meta:
		author = "AlienVault Labs"
		info = "CommentCrew-threat-apt1"
		description = "Detects BOUNCER DLL used by APT1 threat group"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "new_connection_to_bounce():" wide ascii
		$s2 = "usage:%s IP port [proxip] [port] [key]" wide ascii

	condition:
		all of them
}
