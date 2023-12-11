rule connectback2_pl
{
	meta:
		description = "Semi-Auto-generated  - file connectback2.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "473b7d226ea6ebaacc24504bd740822e"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   "
		$s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel"
		$s2 = "ConnectBack Backdoor"

	condition:
		1 of them
}
