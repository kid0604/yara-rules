import "pe"

rule Oilrig_IntelSecurityManager_macro
{
	meta:
		description = "Detects OilRig malware"
		author = "Eyal Sela (slightly modified by Florian Roth)"
		reference = "Internal Research"
		date = "2018-01-19"
		os = "windows"
		filetype = "script"

	strings:
		$one1 = "$c$m$$d$.$$" ascii wide
		$one2 = "$C$$e$r$$t$u$$t$i$$l$" ascii wide
		$one3 = "$$%$a$$p$p$$d$a$" ascii wide
		$one4 = ".$t$$x$t$$" ascii wide
		$one5 = "cu = Replace(cu, \"$\", \"\")" ascii wide
		$one6 = "Shell Environ$(\"COMSPEC\") & \" /c"
		$one7 = "echo \" & Chr(32) & cmd & Chr(32) & \" > \" & Chr(34)" ascii wide
		$two1 = "& SchTasks /Delete /F /TN " ascii wide
		$two2 = "SecurityAssist" ascii wide
		$two3 = "vbs = \"cmd.exe /c SchTasks" ascii wide
		$two4 = "/Delete /F /TN Conhost & del" ascii wide
		$two5 = "NullRefrencedException" ascii wide
		$two6 = "error has occurred in user32.dll by" ascii wide
		$two7 = "NullRefrencedException" ascii wide

	condition:
		filesize <300KB and 1 of ($one*) or 2 of ($two*)
}
