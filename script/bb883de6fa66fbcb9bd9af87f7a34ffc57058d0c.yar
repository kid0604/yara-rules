rule vbs_mykings_botnet
{
	meta:
		description = "Detect the risk of Botnet Malware Mykings Rule 1"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "fso.DeleteFile(WScript.ScriptFullName)" fullword ascii
		$s2 = "Set ws = CreateObject(\"Wscript.Shell\")" fullword ascii
		$s3 = "Set fso = CreateObject(\"Scripting.Filesystemobject\")" fullword ascii
		$r = /Windows\\ime|web|inf|\\c[0-9].bat/

	condition:
		uint16(0)==0x6553 and filesize <1KB and any of ($s*) and $r
}
