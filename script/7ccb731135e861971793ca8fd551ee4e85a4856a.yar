rule Txt_aspxlcx
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "453dd3160db17d0d762e032818a5a10baf234e03"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "public string remoteip = " ascii
		$s2 = "=Dns.Resolve(host);" ascii
		$s3 = "public string remoteport = " ascii
		$s4 = "public class PortForward" ascii

	condition:
		uint16(0)==0x253c and filesize <18KB and all of them
}
