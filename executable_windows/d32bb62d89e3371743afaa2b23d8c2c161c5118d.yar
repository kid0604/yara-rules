rule macrocheck : maldoc
{
	meta:
		Author = "Fireeye Labs"
		Date = "2014/11/30"
		Description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
		Reference = "https://www.fireeye.com/blog/threat-research/2014/11/fin4_stealing_insid.html"
		description = "Yara rule for detecting APT Loader MSIL LUALOADER 1"
		os = "windows"
		filetype = "executable"

	strings:
		$PARAMpword = "pword=" ascii wide
		$PARAMmsg = "msg=" ascii wide
		$PARAMuname = "uname=" ascii
		$userform = "UserForm" ascii wide
		$userloginform = "UserLoginForm" ascii wide
		$invalid = "Invalid username or password" ascii wide
		$up1 = "uploadPOST" ascii wide
		$up2 = "postUpload" ascii wide

	condition:
		all of ($PARAM*) or (($invalid or $userloginform or $userform) and ($up1 or $up2))
}
