rule CN_Tools_item
{
	meta:
		description = "Chinese Hacktool Set - file item.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a584db17ad93f88e56fd14090fae388558be08e4"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
		$s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
		$s3 = "$sWget=\"index.asp\";" fullword ascii
		$s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii

	condition:
		filesize <4KB and all of them
}
