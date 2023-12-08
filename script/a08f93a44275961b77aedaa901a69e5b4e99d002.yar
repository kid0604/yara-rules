rule CobaltStrike_Resources__Template_Vbs_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/btemplate.vbs signature for versions v3.3 to v4.x"
		hash = "e0683f953062e63b2aabad7bc6d76a78748504b114329ef8e2ece808b3294135"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "script"

	strings:
		$ea = "Excel.Application" nocase
		$vis = "Visible = False" nocase
		$wsc = "Wscript.Shell" nocase
		$regkey1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\" nocase
		$regkey2 = "\\Excel\\Security\\AccessVBOM" nocase
		$regwrite = ".RegWrite" nocase
		$dw = "REG_DWORD"
		$code = ".CodeModule.AddFromString"
		$ao = { 41 75 74 6f 5f 4f 70 65 6e }
		$da = ".DisplayAlerts"

	condition:
		all of them
}
