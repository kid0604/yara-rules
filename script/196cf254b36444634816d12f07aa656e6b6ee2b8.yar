rule mimipenguin_2
{
	meta:
		description = "Detects Mimipenguin hack tool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/huntergregal/mimipenguin"
		date = "2017-07-08"
		hash1 = "453bffa90d99a820e4235de95ec3f7cc750539e4023f98ffc8858f9b3c15d89a"
		os = "linux"
		filetype = "script"

	strings:
		$x1 = "DUMP=$(strings \"/tmp/dump.${pid}\" | grep -E" fullword ascii
		$x2 = "strings /tmp/apache* | grep -E '^Authorization: Basic.+=$'" fullword ascii
		$x3 = "grep -E '^_pammodutil_getpwnam_root_1$' -B 5 -A" fullword ascii
		$x4 = "strings \"/tmp/dump.${pid}\" | grep -E -m 1 '^\\$.\\$.+\\$')\"" fullword ascii
		$x5 = "if [[ -n $(ps -eo pid,command | grep -v 'grep' | grep gnome-keyring) ]]; then" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <20KB and 1 of them )
}
