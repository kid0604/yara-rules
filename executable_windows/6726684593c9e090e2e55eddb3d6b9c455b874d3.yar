rule SLServer_campaign_code
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		date = "2016/04/18"
		score = 75
		description = "Searches for the related campaign code."
		os = "windows"
		filetype = "executable"

	strings:
		$campaign = "wthkdoc0106"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and $campaign
}
