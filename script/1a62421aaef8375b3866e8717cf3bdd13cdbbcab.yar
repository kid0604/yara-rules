import "pe"

rule SUSP_OBFUSC_JS_Sept21_2
{
	meta:
		description = "Detects JavaScript obfuscation as used in MalDocs by FIN7 group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.anomali.com/blog/cybercrime-group-fin7-using-windows-11-alpha-themed-docs-to-drop-javascript-backdoor"
		date = "2021-09-07"
		score = 65
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "=new RegExp(String.fromCharCode(" ascii
		$s2 = ".charCodeAt(" ascii
		$s3 = ".substr(0, " ascii
		$s4 = "var shell = new ActiveXObject(" ascii
		$s5 = "= new Date().getUTCMilliseconds();" ascii
		$s6 = ".deleteFile(WScript.ScriptFullName);" ascii

	condition:
		filesize <6000KB and (4 of them )
}
