rule webshell_asp_Ajan
{
	meta:
		description = "Web Shell - file Ajan.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b6f468252407efc2318639da22b08af0"
		os = "windows"
		filetype = "script"

	strings:
		$s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate"

	condition:
		all of them
}
