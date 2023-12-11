import "pe"

rule Vinsula_Sayad_Binder : infostealer binder
{
	meta:
		Author = "Vinsula, Inc"
		Date = "2014/06/20"
		Description = "Sayad Infostealer Binder"
		Reference = "http://vinsula.com/2014/07/20/sayad-flying-kitten-infostealer-malware/"
		description = "Sayad Infostealer Binder"
		os = "windows"
		filetype = "executable"

	strings:
		$pdbstr = "\\Projects\\C#\\Sayad\\Source\\Binder\\obj\\Debug\\Binder.pdb"
		$delphinativestr = "DelphiNative.dll" nocase
		$sqlite3str = "sqlite3.dll" nocase
		$winexecstr = "WinExec"
		$sayadconfig = "base.dll" wide

	condition:
		all of them
}
