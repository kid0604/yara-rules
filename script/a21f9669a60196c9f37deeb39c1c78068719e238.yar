rule item_301
{
	meta:
		description = "Chinese Hacktool Set - file item-301.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15636f0e7dc062437608c1f22b1d39fa15ab2136"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
		$s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
		$s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
		$s4 = "$sURL = $aArg[0];" fullword ascii

	condition:
		filesize <3KB and 3 of them
}
