import "pe"

rule GoldDragon_Aux_File
{
	meta:
		description = "Detects export from Gold Dragon - February 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
		date = "2018-02-03"
		score = 90
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "/////////////////////regkeyenum////////////" ascii

	condition:
		filesize <500KB and 1 of them
}
