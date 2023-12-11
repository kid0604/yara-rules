rule ChinaChopper_one
{
	meta:
		description = "Chinese Hacktool Set - file one.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6cd28163be831a58223820e7abe43d5eacb14109"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "<%eval request(" ascii

	condition:
		filesize <50 and all of them
}
