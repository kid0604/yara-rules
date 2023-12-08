rule SocGholish_JS_22_02_2022
{
	meta:
		description = "Detects SocGholish fake update Javascript files 22.02.2022"
		author = "Wojciech Cieślak"
		date = "2022-02-22"
		hash = "3e14d04da9cc38f371961f6115f37c30"
		hash = "dffa20158dcc110366f939bd137515c3"
		hash = "afee3af324951b1840c789540d5c8bff"
		hash = "c04a1625efec27fb6bbef9c66ca8372b"
		hash = "d08a2350df5abbd8fd530cff8339373e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "encodeURIComponent(''+" ascii
		$s2 = "['open']('POST'," ascii
		$s3 = "new ActiveXObject('MSXML2.XMLHTTP');" ascii

	condition:
		filesize <5KB and all of them
}
