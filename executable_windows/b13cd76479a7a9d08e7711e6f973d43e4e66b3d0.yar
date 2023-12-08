import "pe"

rule APT12_Malware_Aug17
{
	meta:
		description = "Detects APT 12 Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.macnica.net/blog/2017/08/post-fb81.html"
		date = "2017-08-30"
		hash1 = "dc7521c00ec2534cf494c0263ddf67ea4ba9915eb17bdc0b3ebe9e840ec63643"
		hash2 = "42da51b69bd6625244921a4eef9a2a10153e012a3213e8e9877cf831aea3eced"
		os = "windows"
		filetype = "executable"

	condition:
		( uint16(0)==0x5a4d and pe.imphash()=="9ba915fd04f248ad62e856c7238c0264")
}
