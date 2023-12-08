rule ChinaChopper_temp
{
	meta:
		description = "Chinese Hacktool Set - file temp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b0561ea52331c794977d69704345717b4eb0a2a7"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
		$s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
		$s2 = "o.language = \"vbscript\"" fullword ascii
		$s3 = "o.addcode(Request(\"SC\"))" fullword ascii

	condition:
		filesize <1KB and all of them
}
