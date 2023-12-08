rule Txt_aspx1
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
		$s1 = "],\"unsafe\");%>" fullword ascii

	condition:
		filesize <150 and all of them
}
