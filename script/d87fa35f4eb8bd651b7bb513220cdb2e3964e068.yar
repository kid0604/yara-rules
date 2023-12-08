rule WebShell_toolaspshell
{
	meta:
		description = "PHP Webshells Github Archive - file toolaspshell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "11d236b0d1c2da30828ffd2f393dd4c6a1022e3f"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "cprthtml = \"<font face='arial' size='1'>RHTOOLS 1.5 BETA(PVT) Edited By KingDef"
		$s12 = "barrapos = CInt(InstrRev(Left(raiz,Len(raiz) - 1),\"\\\")) - 1" fullword
		$s20 = "destino3 = folderItem.path & \"\\index.asp\"" fullword

	condition:
		2 of them
}
