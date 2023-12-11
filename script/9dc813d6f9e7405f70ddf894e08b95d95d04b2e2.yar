rule HTA_with_WScript_Shell
{
	meta:
		description = "Detects WScript Shell in HTA"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/msftmmpc/status/877396932758560768"
		date = "2017-06-21"
		score = 80
		hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "<hta:application windowstate=\"minimize\"/>"
		$s2 = "<script>var b=new ActiveXObject(\"WScript.Shell\");" ascii

	condition:
		all of them
}
