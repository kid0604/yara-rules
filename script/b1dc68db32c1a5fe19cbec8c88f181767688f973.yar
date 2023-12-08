rule Windows_Trojan_Parallax_b4ea4f1a
{
	meta:
		author = "Elastic Security"
		id = "b4ea4f1a-4b78-4bb8-878e-40fe753018e9"
		fingerprint = "5c695f6b1bb0e72a070e076402cd94a77b178809617223b6caac6f6ec46f2ea1"
		creation_date = "2022-09-08"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.Parallax"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan Parallax"
		filetype = "script"

	strings:
		$parallax_payload_strings_0 = "[Ctrl +" ascii wide fullword
		$parallax_payload_strings_1 = "[Ctrl]" ascii wide fullword
		$parallax_payload_strings_2 = "Clipboard Start" ascii wide fullword
		$parallax_payload_strings_3 = "[Clipboard End]" ascii wide fullword
		$parallax_payload_strings_4 = "UN.vbs" ascii wide fullword
		$parallax_payload_strings_5 = "lt +" ascii wide fullword
		$parallax_payload_strings_6 = "lt]" ascii wide fullword
		$parallax_payload_strings_7 = ".DeleteFile(Wscript.ScriptFullName)" ascii wide fullword
		$parallax_payload_strings_8 = ".DeleteFolder" ascii wide fullword
		$parallax_payload_strings_9 = ".DeleteFile " ascii wide fullword
		$parallax_payload_strings_10 = "Scripting.FileSystemObject" ascii wide fullword
		$parallax_payload_strings_11 = "On Error Resume Next" ascii wide fullword
		$parallax_payload_strings_12 = "= CreateObject" ascii wide fullword
		$parallax_payload_strings_13 = ".FileExists" ascii wide fullword

	condition:
		7 of ($parallax_payload_strings_*)
}
