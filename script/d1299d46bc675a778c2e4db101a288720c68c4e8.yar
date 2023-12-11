rule f3_diy
{
	meta:
		description = "Chinese Hacktool Set - file diy.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f39c2f64abe5e86d8d36dbb7b1921c7eab63bec9"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
		$s5 = ".black {" fullword ascii

	condition:
		uint16(0)==0x253c and filesize <10KB and all of them
}
