rule ChinaChopper_temp_3
{
	meta:
		description = "Chinese Hacktool Set - file temp.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
		$s1 = "\"],\"unsafe\");%>" ascii

	condition:
		uint16(0)==0x253c and filesize <150 and all of them
}
