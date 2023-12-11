rule HYTop_DevPack_fso
{
	meta:
		description = "Webshells Auto-generated - file fso.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b37f3cde1a08890bd822a182c3a881f6"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<!-- PageFSO Below -->"
		$s1 = "theFile.writeLine(\"<script language=\"\"vbscript\"\" runat=server>if request(\"\"\"&cli"

	condition:
		all of them
}
