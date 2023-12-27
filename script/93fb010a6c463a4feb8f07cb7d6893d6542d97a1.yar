import "pe"

rule suspicious_obfuscated_script_detection
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "Observed strings with suspicious AutoIT scripts"
		os = "windows"
		filetype = "script"

	strings:
		$a = "NoTrayIcon" ascii
		$b = "Global" ascii
		$c = "StringTrimLeft" ascii
		$d = "StringTrimRight" ascii
		$e = "StringReverse" ascii

	condition:
		all of them and filesize <3MB
}
