rule CN_Honker_Webshell_Injection_Transit_jmPost
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jmPost.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f80ec26bbdc803786925e8e0450ad7146b2478ff"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "response.write  PostData(JMUrl,JmStr,JmCok,JmRef)" fullword ascii
		$s2 = "JmdcwName=request(\"jmdcw\")" fullword ascii

	condition:
		filesize <9KB and all of them
}
