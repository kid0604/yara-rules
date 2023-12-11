rule CN_Honker_Injection_Transit_jmCook
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file jmCook.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5e1851c77ce922e682333a3cb83b8506e1d7395d"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = ".Open \"POST\",PostUrl,False" fullword ascii
		$s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii

	condition:
		filesize <9KB and all of them
}
