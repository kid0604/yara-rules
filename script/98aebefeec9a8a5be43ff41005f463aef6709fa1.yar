rule CN_Honker_Webshell_Tuoku_script_mysql
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mysql.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8e242c40aabba48687cfb135b51848af4f2d389d"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "txtpassword.Attributes.Add(\"onkeydown\", \"SubmitKeyClick('btnLogin');\");" fullword ascii
		$s2 = "connString = string.Format(\"Host = {0}; UserName = {1}; Password = {2}; Databas" ascii

	condition:
		filesize <202KB and all of them
}
