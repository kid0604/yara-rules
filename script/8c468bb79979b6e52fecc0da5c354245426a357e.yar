rule admin_ad
{
	meta:
		description = "Webshells Auto-generated - file admin-ad.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e6819b8f8ff2f1073f7d46a0b192f43b"
		os = "windows"
		filetype = "script"

	strings:
		$s6 = "<td align=\"center\"> <input name=\"cmd\" type=\"text\" id=\"cmd\" siz"
		$s7 = "Response.write\"<a href='\"&url&\"?path=\"&Request(\"oldpath\")&\"&attrib=\"&attrib&\"'><"

	condition:
		all of them
}
