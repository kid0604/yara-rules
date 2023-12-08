rule oracle_data
{
	meta:
		description = "Chinese Hacktool Set - file oracle_data.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6cf070017be117eace4752650ba6cf96d67d2106"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
		$s1 = "if(isset($_REQUEST['id']))" fullword ascii
		$s2 = "$id=$_REQUEST['id'];" fullword ascii

	condition:
		all of them
}
