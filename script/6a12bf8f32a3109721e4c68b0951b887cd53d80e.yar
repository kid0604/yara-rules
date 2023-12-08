rule Txt_asp_alt_1
{
	meta:
		description = "Chinese Hacktool Set - Webshells - file asp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-14"
		hash = "a63549f749f4d9d0861825764e042e299e06a705"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
		$s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii

	condition:
		uint16(0)==0x253c and filesize <100KB and all of them
}
