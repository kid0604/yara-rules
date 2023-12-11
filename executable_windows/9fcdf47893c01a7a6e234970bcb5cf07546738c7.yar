import "pe"

rule keyboy_related_exports
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the new 2016 sample's export"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"
		description = "Matches the new 2016 sample's export"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <200KB and pe.exports("Embedding") or pe.exports("SSSS") or pe.exports("GetUP")
}
