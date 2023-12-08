import "pe"

rule MALWARE_Win_WSHRATJS
{
	meta:
		author = "ditekSHen"
		description = "Detects WSHRAT JS variants"
		os = "windows"
		filetype = "script"

	strings:
		$charset_full = "us-ascii" nocase ascii
		$charset_begin = "\"us-\"" nocase ascii
		$charset_end = "Array(97,115,99,105,105)" nocase ascii
		$wsc_object1 = "WScript.CreateObject(\"System.Text.UTF8Encoding" nocase ascii
		$wsc_object2 = "WScript.CreateObject(\"Adodb.Stream" nocase ascii
		$wsc_object3 = "WScript.CreateObject(\"Microsoft.XmlDom" nocase ascii
		$s1 = "function(){return" ascii
		$s2 = "}catch(err){" ascii
		$s3 = "{item: \"bin.base64\"}" nocase ascii
		$s4 = "* 1].item =" ascii

	condition:
		filesize <400KB and ($charset_full or ($charset_begin and $charset_end)) and 2 of ($wsc_object*) and 3 of ($s*)
}
