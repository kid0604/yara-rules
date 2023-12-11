rule APT_Project_Sauron_Scripts_alt_1
{
	meta:
		description = "Detects scripts (mostly LUA) from Project Sauron report by Kaspersky"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "local t = w.exec2str(\"regedit "
		$x2 = "local r = w.exec2str(\"cat"
		$x3 = "ap*.txt link*.txt node*.tun VirtualEncryptedNetwork.licence"
		$x4 = "move O FakeVirtualEncryptedNetwork.dll"
		$x5 = "sinfo | basex b 32url | dext l 30"
		$x6 = "w.exec2str(execStr)"
		$x7 = "netnfo irc | basex b 32url"
		$x8 = "w.exec(\"wfw status\")"
		$x9 = "exec(\"samdump\")"
		$x10 = "cat VirtualEncryptedNetwork.ini|grep"
		$x11 = "if string.lower(k) == \"securityproviders\" then"
		$x12 = "exec2str(\"plist b | grep netsvcs\")"
		$x14 = "SAURON_KBLOG_KEY ="

	condition:
		1 of them
}
