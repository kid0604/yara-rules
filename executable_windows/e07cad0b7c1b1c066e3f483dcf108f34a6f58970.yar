rule SLServer_dialog_remains
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks / modified by Florian Roth"
		date = "2016/04/18"
		score = 75
		description = "Searches for related dialog remnants."
		os = "windows"
		filetype = "executable"

	strings:
		$slserver = "SLServer" wide fullword
		$fp1 = "Dell Inc." wide fullword
		$fp2 = "ScriptLogic Corporation" wide
		$extra1 = "SLSERVER" wide fullword
		$extra2 = "\\SLServer.pdb" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and not 1 of ($fp*) and 1 of ($extra*) and $slserver
}
