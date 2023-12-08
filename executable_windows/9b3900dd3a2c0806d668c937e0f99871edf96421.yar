rule Windows_Trojan_Trickbot_217b9c97
{
	meta:
		author = "Elastic Security"
		id = "217b9c97-a637-49b8-a652-5a42ea19ee8e"
		fingerprint = "7d5dcb60526a80926bbaa7e3cd9958719e326a160455095ff9f0315e85b8adf6"
		creation_date = "2021-03-29"
		last_modified = "2021-08-23"
		description = "Targets pwgrab64.dll module containing functionality use to retrieve local passwords"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "1E90A73793017720C9A020069ED1C87879174C19C3B619E5B78DB8220A63E9B7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "pwgrab.dll" ascii fullword
		$a2 = "\\\\.\\pipe\\pidplacesomepipe" ascii fullword
		$a3 = "\\Google\\Chrome\\User Data\\Default\\Login Data.bak" ascii fullword
		$a4 = "select origin_url, username_value, password_value, length(password_value) from logins where blacklisted_by_user = 0" ascii fullword
		$a5 = "<moduleconfig><autostart>yes</autostart><all>yes</all><needinfo name=\"id\"/><needinfo name=\"ip\"/><autoconf><conf ctl=\"dpost"
		$a6 = "Grab_Passwords_Chrome(0)" ascii fullword
		$a7 = "Grab_Passwords_Chrome(1)" ascii fullword
		$a8 = "=\"dpost\" period=\"60\"/></autoconf></moduleconfig>" ascii fullword
		$a9 = "Grab_Passwords_Chrome(): Can't open database" ascii fullword
		$a10 = "UPDATE %Q.%s SET sql = CASE WHEN type = 'trigger' THEN sqlite_rename_trigger(sql, %Q)ELSE sqlite_rename_table(sql, %Q) END, tbl_"
		$a11 = "Chrome login db copied" ascii fullword
		$a12 = "Skip Chrome login db copy" ascii fullword
		$a13 = "Mozilla\\Firefox\\Profiles\\" ascii fullword
		$a14 = "Grab_Passwords_Chrome() success" ascii fullword
		$a15 = "No password provided by user" ascii fullword
		$a16 = "Chrome login db should be copied (copy absent)" ascii fullword
		$a17 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" wide fullword

	condition:
		4 of ($a*)
}
