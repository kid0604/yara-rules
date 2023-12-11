rule webshell_elmaliseker_2
{
	meta:
		description = "Web Shell - file elmaliseker.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
		$s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"

	condition:
		all of them
}
