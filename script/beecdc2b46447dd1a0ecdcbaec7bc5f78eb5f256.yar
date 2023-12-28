rule DragonOK_sysget_strings
{
	meta:
		description = "sysget malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "a9a63b182674252efe32534d04f0361755e9f2f5d82b086b7999a313bd671348"
		os = "windows"
		filetype = "script"

	strings:
		$netbridge = "\\netbridge" wide
		$post = "POST" wide
		$cmd = "cmd /c " wide
		$register = "index.php?type=register&pageinfo" wide

	condition:
		($netbridge and $post and $cmd) or $register
}
