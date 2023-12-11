rule MiniDionis_VBS_Dropped
{
	meta:
		description = "Dropped File - 1.vbs"
		author = "Florian Roth"
		reference = "https://malwr.com/analysis/ZDc4ZmIyZDI4MTVjNGY5NWI0YzE3YjIzNGFjZTcyYTY/"
		date = "2015-07-21"
		hash = "97dd1ee3aca815eb655a5de9e9e8945e7ba57f458019be6e1b9acb5731fa6646"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Wscript.Sleep 5000" ascii
		$s2 = "Set FSO = CreateObject(\"Scripting.FileSystemObject\")" ascii
		$s3 = "Set WshShell = CreateObject(\"WScript.Shell\")" ascii
		$s4 = "If(FSO.FileExists(\"" ascii
		$s5 = "then FSO.DeleteFile(\".\\" ascii

	condition:
		filesize <1KB and all of them and $s1 in (0..40)
}
