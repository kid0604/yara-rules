import "pe"

rule MSBuild_Mimikatz_Execution_via_XML
{
	meta:
		description = "Detects an XML that executes Mimikatz on an endpoint via MSBuild"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://gist.github.com/subTee/c98f7d005683e616560bda3286b6a0d8#file-katz-xml"
		date = "2016-10-07"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "<Project ToolsVersion=" ascii
		$x2 = "</SharpLauncher>" fullword ascii
		$s1 = "\"TVqQAAMAAAA" ascii
		$s2 = "System.Convert.FromBase64String(" ascii
		$s3 = ".Invoke(" ascii
		$s4 = "Assembly.Load(" ascii
		$s5 = ".CreateInstance(" ascii

	condition:
		all of them
}
