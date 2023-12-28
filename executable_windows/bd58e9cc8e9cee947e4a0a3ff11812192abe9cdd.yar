rule Lazarus_BTREE_str
{
	meta:
		description = "BTREE malware using Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "4fb31b9f5432fd09f1fa51a35e8de98fca6081d542827b855db4563be2e50e58"
		os = "windows"
		filetype = "executable"

	strings:
		$command1 = "curl -A cur1-agent -L %s -s -d da" ascii wide
		$command2 = "cmd /c timeout /t 10 & rundll32 \"%s\" #1" ascii wide
		$command3 = "rundll32.exe %s #1 %S" ascii wide
		$command4 = "%s\\marcoor.dll" ascii wide
		$rc4key = "FaDm8CtBH7W660wlbtpyWg4jyLFbgR3IvRw6EdF8IG667d0TEimzTiZ6aBteigP3" ascii wide

	condition:
		2 of ($command*) or $rc4key
}
