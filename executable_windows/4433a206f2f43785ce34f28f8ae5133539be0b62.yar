rule Gen_Net_LocalGroup_Administrators_Add_Command
{
	meta:
		description = "Detects an executable that contains a command to add a user account to the local administrators group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-07-08"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 1 of them )
}
