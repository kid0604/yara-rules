rule Obfuscated_JS_April17
{
	meta:
		description = "Detects cloaked Mimikatz in JS obfuscation"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-04-21"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "\";function Main(){for(var " ascii
		$s2 = "=String.fromCharCode(parseInt(" ascii
		$s3 = "));(new Function(" ascii

	condition:
		filesize <500KB and all of them
}
