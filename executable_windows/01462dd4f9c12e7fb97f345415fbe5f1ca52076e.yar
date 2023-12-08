rule SLServer_dialog_remains_alt_1
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Searches for related dialog remnants."
		ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
		description = "Searches for related dialog remnants."
		os = "windows"
		filetype = "executable"

	strings:
		$slserver = "SLServer" wide

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and $slserver
}
